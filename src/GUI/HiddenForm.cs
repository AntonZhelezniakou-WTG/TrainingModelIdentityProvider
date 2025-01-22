using System.Runtime.InteropServices;

namespace TrainingModelOAuth.GUI;

public sealed class HiddenForm : Form
{
	const string HiddenFormCaption = "TrainingModelOAuth_19125226-A9B2-4D67-8080-842EBA149E22";

	NotifyIcon? trayIcon;
	readonly ContextMenuStrip trayMenu;
	readonly ServerConfiguration serverConfiguration;

	public HiddenForm(ServerConfiguration serverConfiguration)
	{
		this.serverConfiguration = serverConfiguration;

		Text = HiddenFormCaption;
		WindowState = FormWindowState.Minimized;
		ShowInTaskbar = false;
		Visible = false;

		trayIcon = new NotifyIcon();
		trayIcon.Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!);
		trayIcon.Text = "Tray Icon App";
		trayIcon.Visible = true;

		trayMenu = new ContextMenuStrip();
		trayMenu.Items.Add("E&xit", null, Exit);

		trayIcon.ContextMenuStrip = trayMenu;
	}

	[DllImport("user32.dll", SetLastError = true)]
	static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

	public static bool DoesWindowExist => FindWindow(null, HiddenFormCaption) != IntPtr.Zero;

	void Exit(object? sender, EventArgs eventArgs)
	{
		trayMenu.Hide();
		var localTrayIcon = Interlocked.Exchange(ref trayIcon, null);
		if (localTrayIcon != null)
		{
			localTrayIcon.Visible = false;
			localTrayIcon.Dispose();
		}
		Close();
	}

	protected override void OnLoad(EventArgs e)
	{
		Visible = false;
		ShowInTaskbar = false;

		base.OnLoad(e);
	}

	protected override void Dispose(bool isDisposing)
	{
		if (isDisposing)
		{
			trayIcon?.Dispose();
			trayMenu.Dispose();
		}
		base.Dispose(isDisposing);
	}
}
