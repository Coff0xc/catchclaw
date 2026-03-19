package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍renderHeader produces the two-line top status bar.
func renderHeader(m *Model, width int) string {
	// Line 1: brand + connection info
	brand := headerTitleStyle.Render(" 🦞 LobsterGuard v" + Version + " ")

	targetVal := "(未设置)"
	if m.target.Host != "" {
		targetVal = m.target.String()
	}

	tokenVal := "(无)"
	if m.token != "" {
		if len(m.token) > 8 {
			tokenVal = m.token[:4] + "..." + m.token[len(m.token)-4:]
		} else {
			tokenVal = m.token
		}
	}

	tlsVal := "OFF"
	if m.useTLS {
		tlsVal = "ON"
	}

	line1 := fmt.Sprintf("%s ─── target: %s │ token: %s │ TLS: %s",
		brand,
		headerValueStyle.Render(targetVal),
		headerValueStyle.Render(tokenVal),
		headerValueStyle.Render(tlsVal),
	)

	// Line 2: progress bar + severity summary OR idle guide
	var line2 string
	if m.scanning {
		pct := 0
		if m.totalNodes > 0 {
			pct = m.doneNodes * 100 / m.totalNodes
		}
		elapsed := time.Since(m.scanStart).Round(time.Second)
		bar := renderInlineBar(pct, 20)
		sevSummary := renderSeveritySummary(m)
		line2 = fmt.Sprintf(" %s %d%% (%d/%d) %s %s       %s",
			bar, pct, m.doneNodes, m.totalNodes,
			statusScanningStyle.Render("扫描中"),
			headerLabelStyle.Render(fmt.Sprintf("%02d:%02d", int(elapsed.Minutes()), int(elapsed.Seconds())%60)),
			sevSummary,
		)
	} else if len(m.findings) > 0 {
		sevSummary := renderSeveritySummary(m)
		line2 = fmt.Sprintf(" %s  %s",
			statusIdleStyle.Render("空闲"),
			sevSummary,
		)
	} else {
		line2 = " " + headerLabelStyle.Render("空闲 — 输入 scan <target> 开始")
	}

	content := line1 + "\n" + line2
	return headerStyle.Width(width).Height(2).MaxWidth(width).Render(content)
}

// renderInlineBar produces a simple block progress bar.
func renderInlineBar(pct, barW int) string {
	filled := barW * pct / 100
	if filled > barW {
		filled = barW
	}
	empty := barW - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	return statusScanningStyle.Render(bar)
}

// renderSeveritySummary returns colored severity counts.
func renderSeveritySummary(m *Model) string {
	var crit, high, med, low int
	for _, f := range m.findings {
		switch f.Severity.String() {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		case "LOW":
			low++
		}
	}
	return fmt.Sprintf("%s %s %s %s",
		findingCritStyle.Render(fmt.Sprintf("CRIT:%d", crit)),
		findingHighStyle.Render(fmt.Sprintf("HIGH:%d", high)),
		findingMedStyle.Render(fmt.Sprintf("MED:%d", med)),
		findingLowStyle.Render(fmt.Sprintf("LOW:%d", low)),
	)
}

// renderMinSizeWarning shows a message when terminal is too small.
func renderMinSizeWarning(width, height int) string {
	msg := fmt.Sprintf("终端尺寸过小: %dx%d\n最低要求: 80x24", width, height)
	return lipgloss.NewStyle().
		Width(width).
		Height(height).
		Align(lipgloss.Center, lipgloss.Center).
		Foreground(colorYellow).
		Render(msg)
}
