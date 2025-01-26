using System.Net.Sockets;
using System.Net;

namespace TrainingModelOAuth;

static class ServerConfigurationExtensions
{
	public static ServerConfiguration GetValidated(this ServerConfiguration serverConfiguration)
	{
		var configuration = serverConfiguration with { };
		if (string.IsNullOrWhiteSpace(configuration.StaffLoginName))
			throw new InvalidOperationException($"{nameof(configuration.StaffLoginName)} can not be empty!");
		if (configuration.ListeningPort is < 1024 or > 49151)
			throw new InvalidOperationException($"{configuration.ListeningPort} port is out of allowed values range (1024 - 49151)!");
		try
		{
			using var tcpListener = new TcpListener(IPAddress.Any, configuration.ListeningPort);
			tcpListener.Start();
		}
		catch (SocketException)
		{
			throw new InvalidOperationException($"Port {configuration.ListeningPort} is already in use!");
		}
		return configuration;
	}
}
