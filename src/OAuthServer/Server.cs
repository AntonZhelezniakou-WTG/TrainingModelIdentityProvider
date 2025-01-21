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
	//const string SecretKey = "TrainingModelOAuth_1B70DC8C-8EA1-454E-8C9A-FD9F64820E9C";

	const string ClaimName = "ZelAnton";
	const string TestRole = "test_user";

	const int TokenLifetime = 1800;

	static IHost? _host;
	static RSACryptoServiceProvider? _rsaCryptoProvider;
	static readonly string Kid = "key-id-1";

	const string rsaKey =
		"""
		<RSAKeyValue>
			<Modulus>ztJZUvmpuEE6S8Hc0pfpyEAawf3GE7RClVxv+FTQQN2GPDipbmuJhOfQksX+cgOb8RBnBn+GC3NXGf8vnUx1ytIm1bWAodtagcKt5JDe8IkJJK1wQXe5aAbcT/vC9CaqI9U2PKrPjaoVHoUPvQB/yHpkecT3WumsGcIA4C0UUfjTpRAckRsWX6+y5PAUruyL+Doj0Q6ZC5FfanibK0Crevx7leOugAWFRUMaBotcKgarubf3G4iYzUX+1Q20nGwDOBrNDoRcTyMMpcMSZWyzAVmo47rb90mmacKG75CaNDwnuihROzOiwj4hVzpwcsNYy8XlLYA5RICsEGUv+ylp0Q==</Modulus>
			<Exponent>AQAB</Exponent>
			<P>9tzx/Pw/wO9brXhBsxS/c3pU8OiDSvF8chwALmkgcx7F2Y8uLP7ez60xvoYqDuLj2gZK86Od7Z8/YSug52H4Xf4CQL9XyXQdPCWBmdEaltN0kEs74FbjAeZJg8UyCpNoEWMWqbyMWRAcVgwMnfDE1kJB1v5v5m2JAYCnexKenNc=</P>
			<Q>1noBzq/Fg0U3AAa7mfwkLEopIYzlZntdCxAp7HTADCrAQ8PMTcomqr2aLOHSabCmonUb1wKvpm7YTv7tuxJOEpqSJHFxFTes84g2Pa8kRrfeByjB7xK825UBYfJvbpPYPg11a0HvcVn0yThZOD3MOoWBZt/Sa7gu21oKDPqgcZc=</Q>
			<DP>e9FQEorW00d63SQPF+pVKG94QSjuCV3cBEPlF2IlI3iQ1dFJ4MmpKdL9u0kBuVu12voDB/bN1IxmNq+yUbvC3in0KVOPjXyO2UcanPLTekjvExyZGKmbzK0bvFrhAYrzzJy9lj76ygUZoVMD1QgZQjoTWeleaN4RtM45srIhGhs=</DP>
			<DQ>s0KWcCIJe4ZGSgdWlYVg1oPFjP0uX1GMmsqPv8p1GbZBrGHiSMJFPz/ptMmqDBxRqkcnVbYxCXJr6Nq56DmMd5ApxbvrQEigjYuziirwrwrO0D0ImsGWiBEqbqsq58k6W+Lz2QnrD1qYdfZa298K637agRlhzhbLUxsWe3Ke11E=</DQ>
			<InverseQ>OIM7Ny3RLHhzti5JEreThzNTigUVLBmozkNNoWekymETW14VJagXf3sWDie/XV1GDcWSos+Q3atbomDftxzNuM4zGWT/jO1IxcclI90CoZp4rtEl5NEUTKJjWyayKqwew6Nhum5xCTXb8LK1vyxS4rvxQGPEElsJkjNd54TH+Bg=</InverseQ>
			<D>REw+ZyI/I7OWlrHcREcaUqCotWsiYBtk6YHvD+iiJOmCjJyBhw9ICHWs8OslTW1Xr9Gk1AaEs39RQip9BMrdEy8219fqNIkFaFhrqFEW7gOy20PTECuDNJEfa+JNzOZ/xPmBwaL+i1+hPcTfH6Dskb2pNHUQ4hrMVG02cNEyJqcWk/DR3fTIxKf+wl3cAZoctjDi4or04/sBYWX3BJY/wc2+7wWnqEUBUIePA5lYGrfDuiaAMe5dcOzP2YnA6zUNKFTwM87YfHq57cd3mXr7RNCst2OMo7NvwSAMQzZaibkZAaXwVnS3otaqGqHOl7qrAXgG3CorCoVxt+AuEmkT6Q==</D>
		</RSAKeyValue>
		""";

	public static void Start()
	{
		_rsaCryptoProvider = new RSACryptoServiceProvider();
		_rsaCryptoProvider.FromXmlString(rsaKey);

		_host = Host.CreateDefaultBuilder()
			.ConfigureWebHostDefaults(webBuilder =>
			{
				webBuilder.UseUrls(ServerAddress);
				webBuilder.ConfigureServices(services =>
				{
					var rsaParams = _rsaCryptoProvider.ExportParameters(false);
					var rsaKey = new RsaSecurityKey(rsaParams)
					{
						KeyId = Kid,
					};

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
								IssuerSigningKey = rsaKey,
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
		_rsaCryptoProvider?.Dispose();
		_rsaCryptoProvider = null;
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
		var parameters = _rsaCryptoProvider.ExportParameters(false);

		var jwks = new
		{
			keys = new[]
			{
				new
				{
					kty = "RSA",
					use = "sig",
					alg = "RS256",
					kid = Kid,
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

		var userId = "ZelAnton";
		var username = "ZelAnton";
		var role = "test_user";

		var identityToken = GenerateIdentityToken(userId, username, role);
		var accessToken = GenerateAccessToken(userId);
		var accessTokenExpiration = DateTime.UtcNow.AddSeconds(TokenLifetime);

		return Results.Json(new
		{
			id_token = identityToken,
			token_type = "Bearer",
			access_token = accessToken,
			access_token_expires_at = accessTokenExpiration,
			sub = userId,
			username,
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

	static string GenerateAccessToken(string userId)
	{
		var tokenHandler = new JwtSecurityTokenHandler();

		var keyParams = _rsaCryptoProvider.ExportParameters(true);
		var rsaKey = new RsaSecurityKey(keyParams)
		{
			KeyId = Kid,
		};

		var claims = new[]
		{
			new Claim(JwtRegisteredClaimNames.Sub, userId),
			new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
			new Claim("Login", "ZelAnton"),
		};

		var signingCredentials = new SigningCredentials(
			rsaKey,
			SecurityAlgorithms.RsaSha256Signature);

		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(claims),
			Expires = DateTime.UtcNow.AddMinutes(30),
			Issuer = ServerAddress,
			Audience = ClientIdentifier,
			SigningCredentials = signingCredentials,
		};

		var token = tokenHandler.CreateToken(tokenDescriptor);
		return tokenHandler.WriteToken(token);
	}

	static string GenerateIdentityToken(string userId, string username, string role)
	{
		var tokenHandler = new JwtSecurityTokenHandler();

		var keyParams = _rsaCryptoProvider.ExportParameters(true);
		var rsaKey = new RsaSecurityKey(keyParams)
		{
			KeyId = Kid,
		};

		var claims = new[]
		{
			new Claim(JwtRegisteredClaimNames.Sub, userId),
			new Claim(JwtRegisteredClaimNames.Name, username),
			new Claim(ClaimTypes.Role, role),
			new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
			new Claim("Login", "ZelAnton"),
		};

		var signingCredentials = new SigningCredentials(
			rsaKey,
			SecurityAlgorithms.RsaSha256Signature);

		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(claims),
			Expires = DateTime.UtcNow.AddMinutes(30),
			Issuer = ServerAddress,
			Audience = ClientIdentifier,
			SigningCredentials = signingCredentials,
		};

		var token = tokenHandler.CreateToken(tokenDescriptor);
		return tokenHandler.WriteToken(token);
	}
}
