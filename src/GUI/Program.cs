using TrainingModelOAuth.GUI;

namespace TrainingModelOAuth.Startup;

static class Program
{
	const string SingletonMutexName = "TrainingModelOAuth_Run_503A9F8E-6C05-4415-B4C7-035D19B3EA36";

	[STAThread]
	static void Main()
	{
		using var mutex = new Mutex(true, SingletonMutexName, out var isNewInstance);

		if (!isNewInstance || HiddenForm.DoesWindowExist())
		{
			MessageBox.Show("Already running!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}

		ApplicationConfiguration.Initialize();
		Application.Run(new HiddenForm());
	}
}
