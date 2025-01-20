using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace TrainingModelOAuth;

public static class Server
{
	const string ServerAddress = "https://localhost:5000";
	const string ClientIdentifier = "OdysseyTrainingModel";
	const string SecretKey = "TrainingModelOAuth_1B70DC8C-8EA1-454E-8C9A-FD9F64820E9C";

	const string ClaimName = "ZelAnton";
	const string TestRole = "test_user";

	static IHost? _host;

	public static void Start()
	{
		_host = Host.CreateDefaultBuilder()
			.ConfigureWebHostDefaults(webBuilder =>
			{
				webBuilder.UseUrls(ServerAddress);
				webBuilder.ConfigureServices(services =>
				{
					var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));

					services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
						.AddJwtBearer(options =>
						{
							options.TokenValidationParameters = new TokenValidationParameters
							{
								ValidateIssuer = true,
								ValidateAudience = true,
								ValidateLifetime = true,
								ValidateIssuerSigningKey = true,
								ValidIssuer = ServerAddress,
								ValidAudience = ClientIdentifier,
								IssuerSigningKey = signingKey,
							};
						});

					services.AddAuthorization();
					services.AddMemoryCache();
				});

				webBuilder.Configure(app =>
				{
					app.Use(DebuggingMiddleware);

					app.UseHttpsRedirection();
					app.UseAuthentication();
					app.UseAuthorization();
					app.UseRouting();

					app.UseEndpoints(endpoints =>
					{
						endpoints.MapGet("/.well-known/openid-configuration", OpenIdConfiguration);
						endpoints.MapGet("/.well-known/jwks.json", Jwks);
						endpoints.MapGet("/authorize", Authorize);
						endpoints.MapPost("/token", (Func<HttpContext, Task<IResult>>)Token);
						endpoints.MapGet("/userinfo", Userinfo); //.RequireAuthorization();
					});
				});
			})
			.Build();

		_host.Start();
	}

	public static void Stop()
	{
		_host?.StopAsync().Wait(500);
		_host?.Dispose();
		_host = null;
	}

	static async Task DebuggingMiddleware(HttpContext context, Func<Task> next)
	{
		Console.WriteLine($"Incoming request: {context.Request.Method} {context.Request.Path}");

		if (context.Request.Path == "/blocked")
		{
			context.Response.StatusCode = 403;
			await context.Response.WriteAsync("Access denied to /blocked");
			return;
		}

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
			id_token_signing_alg_values_supported = new[] { "RS256" },
			scopes_supported = new[] { "openid", "profile", "email" },
			token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
		};

		context.Response.ContentType = "application/json";
		await context.Response.WriteAsJsonAsync(metadata);
	}

	static async Task Jwks(HttpContext context)
	{
		var rsa = new RSACryptoServiceProvider(2048);
		var parameters = rsa.ExportParameters(false);

		var jwks = new
		{
			keys = new[]
			{
				new
				{
					kty = "RSA",
					use = "sig",
					alg = "RS256",
					kid = "key-id-1",
					n = Base64UrlEncoder.Encode(parameters.Modulus),
					e = Base64UrlEncoder.Encode(parameters.Exponent),
				},
			},
		};

		context.Response.ContentType = "application/json";
		await context.Response.WriteAsJsonAsync(jwks);
	}

	static async Task Authorize(HttpContext context)
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

		Claim[] claims = [new (ClaimTypes.Name, ClaimName), new (ClaimTypes.Role, TestRole)];
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
		}, TimeSpan.FromMinutes(5));

		var redirectUrl = $"{redirectUri}?code={authorizationCode}&state={state}";
		context.Response.Redirect(redirectUrl);
	}

	static async Task<IResult> Token(HttpContext context)
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

		var tokenHandler = new JwtSecurityTokenHandler();
		Claim[] claims = [
			new(JwtRegisteredClaimNames.Sub, "ZelAnton"),
			new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
		];

		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(claims),
			Expires = DateTime.UtcNow.AddMinutes(30),
			Issuer = ServerAddress,
			Audience = ClientIdentifier,
			SigningCredentials = new SigningCredentials(
				new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey)),
				SecurityAlgorithms.HmacSha256Signature),
		};

		try
		{
			var token = tokenHandler.CreateToken(tokenDescriptor);
			var tokenString = tokenHandler.WriteToken(token);

			return Results.Json(new { access_token = tokenString, token_type = "Bearer", expires_in = 1800 });
		}
		catch (Exception e)
		{
			return Results.BadRequest(new { error = "Token generation error", error_description = e.Message });
		}
	}

	static IResult Userinfo(HttpContext context)
	{
		var user = context.User;

		if (user.Identity?.IsAuthenticated != true)
		{
			return Results.Unauthorized();
		}

		var userName = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

		return Results.Json(new
		{
			username = userName ?? "Unknown",
			password = "123",
			role = TestRole,
		});
	}
}
