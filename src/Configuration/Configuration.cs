namespace TrainingModelOAuth;

public sealed class Configuration : IConfiguration
{
	static class Defaults
	{
		internal const int DefaultPort = 5000;
		internal const string DefaultUserName = "ZelAnton";
	}

	public ServerConfiguration ActiveServerConfiguration => activeServerConfiguration ??= LoadServerConfiguration();
	ServerConfiguration? activeServerConfiguration;

	static ServerConfiguration LoadServerConfiguration() => new (ListeningPort: Defaults.DefaultPort, StaffLoginName: Defaults.DefaultUserName); // TODO
}
