using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace TrainingModelOAuth;

sealed class Encryption
{
	internal const string Algorithm = "RS256";
	internal const string KeyType = "RSA";
	internal const string KeyUse = "sig";
	internal const string KeyID = "key-id-1";

	public Encryption()
	{
		CryptoProvider = new RSACryptoServiceProvider();
		using var stream = typeof(Server).Assembly.GetManifestResourceStream("TrainingModelOAuth.Properties.RsaKey.xml");
		using var reader = new StreamReader(stream!);
		var rsaKeyXml = reader.ReadToEnd();
		CryptoProvider.FromXmlString(rsaKeyXml);
		Key = new RsaSecurityKey(CryptoProvider.ExportParameters(true)) { KeyId = KeyID };

		lazySigningCredentials = new(() => new SigningCredentials(Key, SecurityAlgorithms.RsaSha256Signature));
	}

	public RSACryptoServiceProvider CryptoProvider { get; }
	public RsaSecurityKey Key { get; }

	public SigningCredentials SigningCredentials => lazySigningCredentials.Value;
	readonly Lazy<SigningCredentials> lazySigningCredentials;
}
