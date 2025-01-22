using System.Net.Sockets;
using System.Net;

namespace TrainingModelOAuth;

static class ServerConfigurationExtensions
{
	public static ServerConfiguration GetValidated(this ServerConfiguration serverConfiguration)
	{
		if (string.IsNullOrWhiteSpace(serverConfiguration.StaffLoginName))
			throw new InvalidOperationException($"{nameof(serverConfiguration.StaffLoginName)} can not be empty!");
		if (serverConfiguration.ListeningPort is < 1024 or > 49151)
			throw new InvalidOperationException($"{serverConfiguration.ListeningPort} port is out of allowed values range (1024 - 49151)!");
		try
		{
			using var tcpListener = new TcpListener(IPAddress.Any, serverConfiguration.ListeningPort);
			tcpListener.Start();
		}
		catch (SocketException)
		{
			throw new InvalidOperationException($"Port {serverConfiguration.ListeningPort} is already in use!");
		}
		return serverConfiguration;
	}
}
