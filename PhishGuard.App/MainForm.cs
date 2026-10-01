using System.Diagnostics;
using PhishGuard.Core.Models;
using PhishGuard.Core.Scanning;

namespace PhishGuard.App;

/// <summary>
/// Main application window: accepts a URL, runs a scan and displays the
/// verdict, score and the full list of detected risk indicators.
/// </summary>
public sealed class MainForm : Form
{
    private readonly UrlScanner _scanner = new();
    private readonly TextBox _inputBox = UiFactory.UrlInput();
    private readonly Button _scanButton = UiFactory.PrimaryButton("Check URL", 110);
    private readonly Button _pasteButton = UiFactory.SecondaryButton("Paste", 72);
    private readonly Button _clearButton = UiFactory.SecondaryButton("Clear", 90);
    private readonly Button _openButton = UiFactory.SecondaryButton("Open link", 110);
    private readonly Label _verdictLabel = UiFactory.Heading("READY", 26F, UiFactory.Muted);
    private readonly Label _summaryLabel;
    private readonly Label _hostLabel;
    private readonly Label _scoreLabel = UiFactory.Heading("Risk score", 12F, UiFactory.Muted);
    private readonly UiFactory.RiskMeter _scoreBar = UiFactory.ScoreBar();
    private readonly ListView _findingsView = UiFactory.FindingsGrid();
    private readonly StatusStrip _statusStrip = new();
    private readonly ToolStripStatusLabel _statusLabel = new();

    private ScanResult? _current;

    /// <summary>Builds and lays out the window.</summary>
    public MainForm()
    {
        Text = "PhishGuard - URL Safety Checker";
        Size = new Size(940, 660);
        MinimumSize = new Size(780, 580);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9F);
        BackColor = Color.FromArgb(250, 250, 252);

        _summaryLabel = UiFactory.Caption(
            "Enter a URL above and press Check URL.",
            20, 62, 868, Color.FromArgb(70, 70, 80));

        _hostLabel = UiFactory.Caption(
            string.Empty,
            20, 84, 868, Color.FromArgb(110, 110, 120));
        _hostLabel.Height = 18;
        _hostLabel.AutoEllipsis = true;
        _hostLabel.Font = new Font("Consolas", 8.5F);

        BuildLayout();
        WireEvents();
        UpdateIdleState();
    }

    private void BuildLayout()
    {
        var header = UiFactory.Heading("PhishGuard", 18F, Color.FromArgb(30, 30, 40));
        header.Location = new Point(20, 16);

        var subtitle = UiFactory.Caption(
            "Paste or type a link to check whether it is safe before you open it.",
            22, 50, 700, UiFactory.Muted);
        subtitle.Height = 20;

        _inputBox.Location = new Point(20, 84);
        _inputBox.Size = new Size(690, 30);
        _inputBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        _inputBox.Text = "https://";

        _scanButton.Location = new Point(720, 83);
        _scanButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;

        _pasteButton.Location = new Point(838, 83);
        _pasteButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;

        // ---- Verdict panel ----------------------------------------------
        var verdictPanel = new Panel
        {
            Location = new Point(20, 128),
            Size = new Size(890, 126),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Padding = new Padding(0)
        };

        // Verdict on the left, risk score on the right of the same row.
        _verdictLabel.Location = new Point(20, 12);
        _scoreLabel.Location = new Point(700, 26);
        _scoreLabel.Size = new Size(170, 24);
        _scoreLabel.TextAlign = ContentAlignment.MiddleRight;

        _summaryLabel.Location = new Point(20, 62);
        _summaryLabel.Height = 22;
        _hostLabel.Location = new Point(20, 84);
        _hostLabel.Height = 18;

        _summaryLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        _hostLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        _scoreLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;

        _scoreBar.Location = new Point(20, 102);
        _scoreBar.Size = new Size(850, 8);
        _scoreBar.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        verdictPanel.Controls.Add(_verdictLabel);
        verdictPanel.Controls.Add(_scoreLabel);
        verdictPanel.Controls.Add(_summaryLabel);
        verdictPanel.Controls.Add(_hostLabel);
        verdictPanel.Controls.Add(_scoreBar);

        // ---- Results grid -----------------------------------------------
        UiFactory.AddFindingsColumns(_findingsView);

        _findingsView.Location = new Point(20, 268);
        _findingsView.Size = new Size(890, 300);
        _findingsView.Anchor = AnchorStyles.Top | AnchorStyles.Bottom |
                              AnchorStyles.Left | AnchorStyles.Right;

        // ---- Bottom actions ---------------------------------------------
        _clearButton.Location = new Point(20, 562);
        _clearButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;

        _openButton.Location = new Point(120, 562);
        _openButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        _openButton.Enabled = false;

        _statusStrip.Items.Add(_statusLabel);
        _statusLabel.Text = "Offline mode: no network requests are made.";
        _statusLabel.Spring = true;
        _statusLabel.TextAlign = ContentAlignment.MiddleLeft;
        _statusStrip.Dock = DockStyle.Bottom;

        Controls.Add(header);
        Controls.Add(subtitle);
        Controls.Add(_inputBox);
        Controls.Add(_scanButton);
        Controls.Add(_pasteButton);
        Controls.Add(verdictPanel);
        Controls.Add(_findingsView);
        Controls.Add(_clearButton);
        Controls.Add(_openButton);
        Controls.Add(_statusStrip);

        AcceptButton = _scanButton;
    }

    private void WireEvents()
    {
        _scanButton.Click += (_, _) => RunScan();
        _pasteButton.Click += (_, _) => PasteFromClipboard();
        _clearButton.Click += (_, _) => ClearAll();
        _openButton.Click += (_, _) => OpenCurrentUrl();

        _findingsView.DoubleClick += (_, _) => ShowFindingDetail();
        _findingsView.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                ShowFindingDetail();
            }
        };

        _inputBox.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                RunScan();
            }
        };
    }

    private void PasteFromClipboard()
    {
        try
        {
            var text = Clipboard.GetText();

            if (!string.IsNullOrWhiteSpace(text))
            {
                _inputBox.Text = text.Trim();
                RunScan();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Could not read the clipboard: " + ex.Message,
                "Clipboard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void RunScan()
    {
        var raw = _inputBox.Text.Trim();

        if (raw.Length == 0)
        {
            MessageBox.Show(this, "Please enter a URL to check.", "PhishGuard",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Cursor = Cursors.WaitCursor;

        try
        {
            _current = _scanner.Scan(raw);
            Render(_current);
            _statusLabel.Text = string.IsNullOrEmpty(_current.Host)
                ? "Input could not be parsed as a URL."
                : $"Scanned {_current.Host} at {_current.ScannedAt.ToLocalTime():HH:mm:ss}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "The scan failed unexpectedly: " + ex.Message,
                "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            Cursor = Cursors.Default;
        }
    }

    private void Render(ScanResult result)
    {
        _findingsView.BeginUpdate();
        _findingsView.Items.Clear();

        foreach (var finding in result.Findings)
        {
            var item = new ListViewItem(finding.Severity.ToTag());
            item.SubItems.Add(finding.Title);
            item.SubItems.Add(finding.Detail);
            item.Tag = finding;
            item.ForeColor = UiFactory.SeverityColor(finding.Severity);

            _findingsView.Items.Add(item);
        }

        _findingsView.EndUpdate();

        _verdictLabel.Text = result.Verdict.ToLabel();
        _verdictLabel.ForeColor = Color.FromArgb((int)result.Verdict.ToArgb());
        _summaryLabel.Text = result.Summary;
        _hostLabel.Text = string.IsNullOrEmpty(result.Host)
            ? "(could not parse input)"
            : result.Host;

        _scoreBar.Value = result.Score;
        _scoreLabel.Text = $"Risk score {result.Score}/100";
        _scoreBar.BarColor = Color.FromArgb((int)result.Verdict.ToArgb());
        _scoreBar.Invalidate();

        _openButton.Enabled = result.IsValid;
    }

    private void ShowFindingDetail()
    {
        if (_findingsView.SelectedItems.Count == 0)
        {
            return;
        }

        if (_findingsView.SelectedItems[0].Tag is RiskFinding finding)
        {
            MessageBox.Show(this,
                finding.Title + "\n\n" +
                $"Code: {finding.Code}\n" +
                $"Severity: {finding.Severity}\n\n" +
                finding.Detail,
                "Indicator detail", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void OpenCurrentUrl()
    {
        var target = _current?.NormalizedUrl;

        if (_current is null || !_current.IsValid || string.IsNullOrEmpty(target))
        {
            return;
        }

        var warning = _current.ShouldWarn
            ? "This link was flagged as DANGEROUS.\n\nOpening it may expose you " +
              "to credential theft or malware.\n\nAre you sure you want to continue?"
            : "Open this link in your default browser?";

        if (MessageBox.Show(this, warning, "Confirm",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(target)
            {
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Could not open the link: " + ex.Message,
                "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ClearAll()
    {
        _inputBox.Text = "https://";
        _findingsView.Items.Clear();
        _current = null;
        UpdateIdleState();
        _inputBox.Focus();
    }

    private void UpdateIdleState()
    {
        _verdictLabel.Text = "READY";
        _verdictLabel.ForeColor = UiFactory.Muted;
        _summaryLabel.Text = "Enter a URL above and press Check URL.";
        _hostLabel.Text = string.Empty;
        _scoreLabel.Text = "Risk score";
        _scoreBar.Value = 0;
        _scoreBar.BarColor = UiFactory.Muted;
        _openButton.Enabled = false;
    }
}