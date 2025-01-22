using TrainingModelOAuth.GUI;

namespace TrainingModelOAuth.Startup;

static class Program
{
	const string SingletonMutexName = "TrainingModelOAuth_Run_503A9F8E-6C05-4415-B4C7-035D19B3EA36";

	const int DefaultPort = 5000;
	const string DefaultUserName = "ZelAnton";

	[STAThread]
	static void Main()
	{
		using var mutex = new Mutex(true, SingletonMutexName, out var isNewInstance);

		if (!isNewInstance || HiddenForm.DoesWindowExist)
		{
			MessageBox.Show("Already running!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}

		ApplicationConfiguration.Initialize();

		var serverConfiguration = new ServerConfiguration(ListeningPort: DefaultPort, StaffLoginName: DefaultUserName);
		var hiddenForm = new HiddenForm(serverConfiguration);
		var server = new Server(serverConfiguration);

		hiddenForm.FormClosed += (_, _) => server.Stop();
		hiddenForm.HandleCreated += (_, _) => server.Start();

		Application.Run(hiddenForm);
	}
}
