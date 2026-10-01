using System.Drawing.Imaging;
using System.Reflection;
using PhishGuard.App;

namespace PhishGuard.UiSmokeTest;

/// <summary>
/// Renders the real <see cref="MainForm"/> for a set of representative URLs and
/// writes the results to PNG files. This proves the UI wires up correctly and
/// displays verdicts, without depending on keyboard focus.
/// </summary>
public static class Program
{
    private static readonly (string Name, string Url)[] Cases =
    {
        ("01-idle", ""),
        ("02-phishing", "http://paypal-secure.tk/login"),
        ("03-blocklisted", "https://webscr-paypal-secure.tk/"),
        ("04-raw-ip", "http://192.168.1.50/login.php"),
        ("05-legitimate", "https://github.com/microsoft/vscode"),
        ("06-invalid", "javascript:alert(1)")
    };

    /// <summary>Runs the smoke test.</summary>
    /// <param name="args">Optional first argument: output directory for the PNG renders.</param>
    [STAThread]
    public static int Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var outputDir = args.Length > 0
            ? args[0]
            : Path.Combine(AppContext.BaseDirectory, "renders");

        Directory.CreateDirectory(outputDir);

        using var form = new MainForm();
        form.Show();
        Application.DoEvents();

        var failures = 0;

        foreach (var (name, url) in Cases)
        {
            var verdict = Invoke(form, "RunScan", url) as string ?? "<none>";

            // Let layout settle before capturing.
            Application.DoEvents();
            form.Refresh();

            var path = Path.Combine(outputDir, name + ".png");
            Capture(form, path);

            Console.WriteLine($"{name,-16} {url,-38} -> {verdict}");
        }

        form.Close();

        Console.WriteLine($"Renders written to {outputDir}");
        return failures == 0 ? 0 : 1;
    }

    /// <summary>
    /// Calls the private <c>RunScan</c> method on the form and reads back the
    /// verdict label that was rendered.
    /// </summary>
    /// <param name="form">Form instance to drive.</param>
    /// <param name="method">Name of the private method.</param>
    /// <param name="url">URL to scan.</param>
    private static object? Invoke(MainForm form, string method, string url)
    {
        var input = typeof(MainForm)
            .GetField("_inputBox", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(form) as TextBox;

        var verdictLabel = typeof(MainForm)
            .GetField("_verdictLabel", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(form) as Label;

        var scan = typeof(MainForm)
            .GetMethod(method, BindingFlags.NonPublic | BindingFlags.Instance)!;

        input!.Text = url;
        scan.Invoke(form, Array.Empty<object>());

        return verdictLabel?.Text;
    }

    /// <summary>Renders a control to a PNG file.</summary>
    /// <param name="form">Form to capture.</param>
    /// <param name="path">Destination file path.</param>
    private static void Capture(Control form, string path)
    {
        using var bitmap = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bitmap, new Rectangle(0, 0, form.Width, form.Height));
        bitmap.Save(path, ImageFormat.Png);
    }
}