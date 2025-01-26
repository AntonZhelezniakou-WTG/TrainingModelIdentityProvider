namespace TrainingModelIdentityProvider;

public interface IServer
{
	ServerConfiguration? StartedConfiguration { get; }
	bool Started { get; }

	public void Start();
	public void Stop();
}
