package tui

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	colorRed     = lipgloss.Color("#FF5555")
	colorOrange  = lipgloss.Color("#FFB86C")
	colorYellow  = lipgloss.Color("#F1FA8C")
	colorGreen   = lipgloss.Color("#50FA7B")
	colorCyan    = lipgloss.Color("#8BE9FD")
	colorBlue    = lipgloss.Color("#6272A4")
	colorPurple  = lipgloss.Color("#BD93F9")
	colorWhite   = lipgloss.Color("#F8F8F2")
	colorDim     = lipgloss.Color("#6272A4")
	colorBg      = lipgloss.Color("#282A36")
	colorBorder  = lipgloss.Color("#44475A")
	colorActiveBorder = lipgloss.Color("#BD93F9")
)

// Severity colors
func severityColor(sev string) lipgloss.Color {
	switch sev {
	case "CRITICAL":
		return colorRed
	case "HIGH":
		return colorOrange
	case "MEDIUM":
		return colorYellow
	case "LOW":
		return colorCyan
	case "INFO":
		return colorDim
	default:
		return colorWhite
	}
}

// Panels
var (
	baseBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	activeBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorActiveBorder)
)

// Header styles
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(lipgloss.Color("#44475A")).
			Padding(0, 1)

	headerLabelStyle = lipgloss.NewStyle().
				Foreground(colorDim)

	headerValueStyle = lipgloss.NewStyle().
				Foreground(colorCyan).
				Bold(true)

	headerTitleStyle = lipgloss.NewStyle().
				Foreground(colorRed).
				Bold(true)
)

// Progress panel styles
var (
	nodeRunningStyle = lipgloss.NewStyle().
				Foreground(colorYellow)

	nodeDoneStyle = lipgloss.NewStyle().
			Foreground(colorGreen)

	nodePendingStyle = lipgloss.NewStyle().
				Foreground(colorDim)

	nodeErrorStyle = lipgloss.NewStyle().
			Foreground(colorRed)

	progressTitleStyle = lipgloss.NewStyle().
				Foreground(colorPurple).
				Bold(true)
)

// Findings table styles
var (
	findingCritStyle = lipgloss.NewStyle().
				Foreground(colorRed).
				Bold(true)

	findingHighStyle = lipgloss.NewStyle().
				Foreground(colorOrange)

	findingMedStyle = lipgloss.NewStyle().
			Foreground(colorYellow)

	findingLowStyle = lipgloss.NewStyle().
			Foreground(colorCyan)

	findingInfoStyle = lipgloss.NewStyle().
				Foreground(colorDim)

	findingsTitleStyle = lipgloss.NewStyle().
				Foreground(colorGreen).
				Bold(true)
)

// Log styles
var (
	logTitleStyle = lipgloss.NewStyle().
			Foreground(colorCyan).
			Bold(true)

	logTimestampStyle = lipgloss.NewStyle().
				Foreground(colorDim)
)

// Input styles
var (
	inputPromptStyle = lipgloss.NewStyle().
				Foreground(colorRed).
				Bold(true)

	inputStyle = lipgloss.NewStyle().
			Foreground(colorWhite)

	inputBoxStyle = lipgloss.NewStyle().
			BorderTop(true).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)
)

// Help styles
var (
	helpKeyStyle = lipgloss.NewStyle().
			Foreground(colorPurple).
			Bold(true)

	helpDescStyle = lipgloss.NewStyle().
			Foreground(colorDim)

	helpSepStyle = lipgloss.NewStyle().
			Foreground(colorBorder)
)

// Status indicator
var (
	statusScanningStyle = lipgloss.NewStyle().
				Foreground(colorYellow).
				Bold(true)

	statusIdleStyle = lipgloss.NewStyle().
			Foreground(colorGreen)

	statusErrorStyle = lipgloss.NewStyle().
				Foreground(colorRed).
				Bold(true)
)

// panelStyle returns style for a panel based on active state.
func panelStyle(active bool, width, height int) lipgloss.Style {
	base := baseBorder
	if active {
		base = activeBorder
	}
	return base.Width(width).Height(height)
}
