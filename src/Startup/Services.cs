using Microsoft.Extensions.DependencyInjection;

namespace TrainingModelIdentityProvider;

static class Services
{
	public static ServiceProvider Init()
	{
		var services = new ServiceCollection();

		services.AddSingleton<IConfiguration, Configuration>();
		services.AddSingleton<IServer, Server>();

		return services.BuildServiceProvider();
	}
}
