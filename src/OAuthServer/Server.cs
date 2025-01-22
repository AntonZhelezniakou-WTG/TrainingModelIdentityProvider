using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace TrainingModelOAuth;

public sealed class Server(IServerConfigurationProvider serverConfigurationProvider) : IServer
{
	const string ClientIdentifier = "OdysseyTrainingModel";
	const int TokenLifetime = 1800;

	public bool Started { get; private set; }

	string ListeningAddress => $"https://localhost:{ActiveConfiguration!.ListeningPort}";
	string StaffLoginName => ActiveConfiguration!.StaffLoginName;

	public ServerConfiguration? ActiveConfiguration { get; private set; }

	IHost? host;

	Encryption Encryption => lazyEncryption.Value;
	readonly Lazy<Encryption> lazyEncryption = new(() => new Encryption());

	public void Start()
	{
		ActiveConfiguration = serverConfigurationProvider.GetConfiguration().GetValidated();

		host = Host.CreateDefaultBuilder()
			.ConfigureWebHostDefaults(webBuilder =>
			{
				webBuilder.UseUrls(ListeningAddress);
				webBuilder.ConfigureServices(services =>
				{
					services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
						.AddJwtBearer(GetJwtBearerConfigureOptions);

					services.AddAuthorization();
					services.AddMemoryCache();
				});

				webBuilder.Configure(app =>
				{
					app.Use(DebuggingMiddleware);

					app.UseHttpsRedirection();
					app.UseRouting();
					app.UseAuthentication();
					app.UseAuthorization();

					app.UseEndpoints(endpoints =>
					{
						endpoints.MapGet("/.well-known/openid-configuration", OpenIdConfiguration);
						endpoints.MapGet("/.well-known/jwks.json", Jwks);
						endpoints.MapGet("/authorize", Authorize);
						endpoints.MapPost("/token", (Func<HttpContext, Task<IResult>>)Token);
						endpoints.MapGet("/userinfo", Userinfo).RequireAuthorization();
					});
				});
			})
			.Build();

		host.Start();
		Started = true;
	}

	void GetJwtBearerConfigureOptions(JwtBearerOptions options)
	{
		options.TokenValidationParameters = new TokenValidationParameters {
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidIssuer = ListeningAddress,
			ValidAudience = ClientIdentifier,
			IssuerSigningKey = Encryption.Key,
		};
	}

	public void Stop()
	{
		Started = false;
		ActiveConfiguration = null;
		host?.StopAsync().Wait(500);
		host?.Dispose();
		host = null;
	}

	static async Task DebuggingMiddleware(HttpContext context, Func<Task> next)
	{
		Console.WriteLine($"Incoming request: {context.Request.Method} {context.Request.Path}");
		await next();
	}

	static async Task OpenIdConfiguration(HttpContext context)
	{
		var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
		var metadata = new
		{
			issuer = baseUrl,
			authorization_endpoint = $"{baseUrl}/authorize",
			token_endpoint = $"{baseUrl}/token",
			userinfo_endpoint = $"{baseUrl}/userinfo",
			jwks_uri = $"{baseUrl}/.well-known/jwks.json",
			response_types_supported = new[] { "code", "token", "id_token", "code id_token", "code token" },
			subject_types_supported = new[] { "public" },
			id_token_signing_alg_values_supported = new[] { Encryption.Algorithm },
			scopes_supported = new[] { "openid", "profile", "email" },
			token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
		};

		context.Response.ContentType = "application/json";
		await context.Response.WriteAsJsonAsync(metadata);
	}

	async Task Jwks(HttpContext context)
	{
		var parameters = Encryption.CryptoProvider.ExportParameters(false);

		var jwks = new
		{
			keys = new[]
			{
				new
				{
					kty = Encryption.KeyType,
					use = Encryption.KeyUse,
					alg = Encryption.Algorithm,
					kid = Encryption.KeyID,
					n = Base64UrlEncoder.Encode(parameters.Modulus),
					e = Base64UrlEncoder.Encode(parameters.Exponent),
				},
			},
		};

		context.Response.ContentType = "application/json";
		await context.Response.WriteAsJsonAsync(jwks);
	}

	async Task Authorize(HttpContext context)
	{
		var responseType = context.Request.Query["response_type"];
		var clientId = context.Request.Query["client_id"];
		var redirectUri = context.Request.Query["redirect_uri"];
		var state = context.Request.Query["state"];
		var codeChallenge = context.Request.Query["code_challenge"];

		if (string.IsNullOrEmpty(responseType) || responseType != "code" ||
			string.IsNullOrEmpty(clientId) || clientId != ClientIdentifier ||
			string.IsNullOrEmpty(redirectUri))
		{
			context.Response.StatusCode = 400;
			await context.Response.WriteAsync("Invalid request");
			return;
		}

		Claim[] claims = [new (ClaimTypes.Name, StaffLoginName)];
		var identity = new ClaimsIdentity(claims, "AuthStub");
		var principal = new ClaimsPrincipal(identity);

		context.User = principal;

		var isAuthenticated = context.User.Identity?.IsAuthenticated == true;

		if (!isAuthenticated)
		{
			var loginPageUrl = $"{redirectUri}?error=login_required&state={state}";
			context.Response.Redirect(loginPageUrl);
			return;
		}

		var authorizationCode = Guid.NewGuid().ToString("N");

		var memoryCache = context.RequestServices.GetRequiredService<IMemoryCache>();
		memoryCache.Set(authorizationCode, new
		{
			RedirectUri = redirectUri,
			CodeChallenge = codeChallenge,
		}, TimeSpan.FromMilliseconds(TokenLifetime) + TimeSpan.FromMinutes(2));

		var redirectUrl = $"{redirectUri}?code={authorizationCode}&state={state}";
		context.Response.Redirect(redirectUrl);
	}

	async Task<IResult> Token(HttpContext context)
	{
		var form = await context.Request.ReadFormAsync();

		var grantType = form["grant_type"];
		var code = form["code"];
		var redirectUri = form["redirect_uri"];
		var codeVerifier = form["code_verifier"];
		var clientId = form["client_id"];

		if (grantType != "authorization_code")
		{
			return Results.BadRequest(new { error = "unsupported_grant_type" });
		}

		if (clientId != ClientIdentifier)
		{
			return Results.BadRequest(new { error = "invalid_client_id" });
		}

		var memoryCache = context.RequestServices.GetRequiredService<IMemoryCache>();
		if (!memoryCache.TryGetValue(code.ToString(), out dynamic? cachedData))
		{
			return Results.BadRequest(new { error = "invalid_code", error_description = "Authorization code is invalid or expired" });
		}

		if (cachedData!.RedirectUri != redirectUri)
		{
			return Results.BadRequest(new { error = "invalid_redirect_uri", error_description = "Redirect URI mismatch" });
		}

		if (!string.IsNullOrEmpty(codeVerifier))
		{
			var computedChallenge = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier!)))
				.Replace("+", "-").Replace("/", "_").Replace("=", "");

			if (computedChallenge != cachedData.CodeChallenge)
			{
				return Results.BadRequest(new { error = "invalid_code_verifier", error_description = "Code verifier does not match the code challenge" });
			}
		}

		var identityToken = GenerateIdentityToken(userId: StaffLoginName, username: StaffLoginName);
		var accessToken = GenerateAccessToken(StaffLoginName);
		var accessTokenExpiration = DateTime.UtcNow.AddMilliseconds(TokenLifetime);

		return Results.Json(new
		{
			id_token = identityToken,
			token_type = "Bearer",
			access_token = accessToken,
			access_token_expires_at = accessTokenExpiration,
			sub = StaffLoginName,
			username = StaffLoginName,
		});
	}

	static IResult Userinfo(HttpContext context)
	{
		var user = context.User;
		if (user.Identity?.IsAuthenticated != true)
		{
			return Results.Unauthorized();
		}

		var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? user.FindFirst(ClaimTypes.Name)?.Value;
		if (string.IsNullOrEmpty(userId))
		{
			return Results.NotFound();
		}

		var username = user.FindFirst(ClaimTypes.Name)?.Value ?? "Unknown";
		var role = user.FindFirst(ClaimTypes.Role)?.Value ?? "Unknown";

		return Results.Json(new
		{
			sub = userId,
			username,
			role,
		});
	}

	string GenerateAccessToken(string userId)
	{
		var tokenHandler = new JwtSecurityTokenHandler();

		var claims = new[]
		{
			new Claim(JwtRegisteredClaimNames.Sub, userId),
			new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
		};

		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(claims),
			Expires = DateTime.UtcNow.AddMilliseconds(TokenLifetime),
			Issuer = ListeningAddress,
			Audience = ClientIdentifier,
			SigningCredentials = Encryption.SigningCredentials,
		};

		var token = tokenHandler.CreateToken(tokenDescriptor);
		return tokenHandler.WriteToken(token);
	}

	string GenerateIdentityToken(string userId, string username)
	{
		var tokenHandler = new JwtSecurityTokenHandler();

		var claims = new[]
		{
			new Claim(JwtRegisteredClaimNames.Sub, userId),
			new Claim(JwtRegisteredClaimNames.Name, username),
			new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
			new Claim("Login", StaffLoginName),
		};

		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(claims),
			Expires = DateTime.UtcNow.AddMinutes(30),
			Issuer = ListeningAddress,
			Audience = ClientIdentifier,
			SigningCredentials = Encryption.SigningCredentials,
		};

		var token = tokenHandler.CreateToken(tokenDescriptor);
		return tokenHandler.WriteToken(token);
	}
}
