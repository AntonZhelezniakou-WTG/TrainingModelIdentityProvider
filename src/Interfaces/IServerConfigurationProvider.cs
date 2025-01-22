namespace TrainingModelOAuth;

public interface IServerConfigurationProvider
{
	public ServerConfiguration GetConfiguration();
}

public record ServerConfiguration(int ListeningPort, string StaffLoginName) : IServerConfigurationProvider
{
	public ServerConfiguration GetConfiguration() => this with { };
}
