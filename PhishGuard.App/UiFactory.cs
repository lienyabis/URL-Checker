using System.Drawing;
using System.Windows.Forms;

namespace PhishGuard.App;

/// <summary>
/// Creates and configures the individual controls used by <see cref="MainForm"/>.
/// Kept separate so the form class stays focused on behaviour.
/// </summary>
internal static class UiFactory
{
    /// <summary>Brand blue used for the primary action button.</summary>
    public static readonly Color Accent = Color.FromArgb(0, 120, 212);

    /// <summary>Neutral grey used for secondary text.</summary>
    public static readonly Color Muted = Color.FromArgb(90, 90, 100);

    /// <summary>Border colour for the verdict panel.</summary>
    public static readonly Color PanelBorder = Color.FromArgb(225, 225, 230);

    /// <summary>Creates a bold title label.</summary>
    public static Label Heading(string text, float size, Color color) => new()
    {
        Text = text,
        Font = new Font("Segoe UI Semibold", size),
        ForeColor = color,
        AutoSize = true
    };

    /// <summary>Creates a secondary descriptive label.</summary>
    public static Label Caption(string text, int x, int y, int width, Color color) => new()
    {
        Text = text,
        ForeColor = color,
        AutoSize = false,
        Size = new Size(width, 40),
        Location = new Point(x, y)
    };

    /// <summary>Creates a monospace text box for URL entry.</summary>
    public static TextBox UrlInput() => new()
    {
        Multiline = false,
        Font = new Font("Consolas", 11F)
    };

    /// <summary>Creates a filled primary button.</summary>
    public static Button PrimaryButton(string text, int width)
    {
        var button = new Button
        {
            Text = text,
            Size = new Size(width, 32),
            BackColor = Accent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            UseVisualStyleBackColor = false
        };

        button.FlatAppearance.BorderSize = 0;
        button.FlatAppearance.MouseOverBackColor = Color.FromArgb(0, 105, 190);

        return button;
    }

    /// <summary>Creates a standard secondary button.</summary>
    public static Button SecondaryButton(string text, int width) => new()
    {
        Text = text,
        Size = new Size(width, 32)
    };

    /// <summary>
    /// A thin horizontal risk meter drawn manually, so its colour always
    /// matches the verdict. The built-in ProgressBar ignores ForeColor when
    /// visual styles are active, which made a safe-looking green bar appear
    /// for dangerous verdicts.
/// </summary>
    public sealed class RiskMeter : Control
    {
        private int _value;

        /// <summary>Creates the meter.</summary>
        public RiskMeter()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
            BackColor = Color.FromArgb(235, 235, 240);
            Height = 8;
        }

        /// <summary>Current risk value, 0 to 100.</summary>
        public int Value
        {
            get => _value;
            set
            {
                var clamped = Math.Clamp(value, 0, 100);

                if (_value != clamped)
                {
                    _value = clamped;
                    Invalidate();
                }
            }
        }

        /// <summary>Bar colour; set from the verdict colour.</summary>
        public Color BarColor { get; set; } = Color.FromArgb(90, 90, 100);

        /// <summary>Draws the track and the filled portion.</summary>
        /// <param name="e">Paint event data.</param>
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            var track = new Rectangle(0, 0, Width, Height);
            using (var trackBrush = new SolidBrush(Color.FromArgb(235, 235, 240)))
            {
                e.Graphics.FillRectangle(trackBrush, track);
            }

            if (_value <= 0)
            {
                return;
            }

            // Scale the filled width to the actual control width.
            var filled = (int)Math.Round(Width * (_value / 100.0));

            using var barBrush = new SolidBrush(BarColor);
            e.Graphics.FillRectangle(barBrush, 0, 0, filled, Height);
        }
    }

    /// <summary>Creates a horizontal risk meter.</summary>
    public static RiskMeter ScoreBar() => new();

    /// <summary>Creates the results grid with its three fixed columns.</summary>
    public static ListView FindingsGrid() => new()
    {
        View = View.Details,
        FullRowSelect = true,
        GridLines = true,
        HideSelection = false,
        MultiSelect = false,
        Font = new Font("Segoe UI", 9F)
    };

    /// <summary>Adds the standard findings columns to a grid.</summary>
    /// <param name="grid">Grid to configure.</param>
    public static void AddFindingsColumns(ListView grid)
    {
        grid.Columns.Add("Severity", 70);
        grid.Columns.Add("Indicator", 220);
        grid.Columns.Add("Explanation", 590);
    }

    /// <summary>Maps a severity onto the colour used to render its row.</summary>
    /// <param name="severity">Severity to colour.</param>
    public static Color SeverityColor(Core.Models.Severity severity) => severity switch
    {
        Core.Models.Severity.Critical => Color.FromArgb(139, 0, 0),
        Core.Models.Severity.High => Color.FromArgb(196, 49, 75),
        Core.Models.Severity.Medium => Color.FromArgb(178, 106, 0),
        _ => Color.FromArgb(70, 70, 80)
    };
}