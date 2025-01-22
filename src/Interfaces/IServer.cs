namespace TrainingModelOAuth;

public interface IServer
{
	ServerConfiguration? ActiveConfiguration { get; }

	public void Start();
	public void Stop();
}
