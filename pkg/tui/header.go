package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// renderHeader produces the top status bar.
func renderHeader(m *Model, width int) string {
	title := headerTitleStyle.Render(" LobsterGuard v4.0.0 ")

	targetVal := "(未设置)"
	if m.target.Host != "" {
		targetVal = m.target.String()
	}
	targetPart := headerLabelStyle.Render("target:") + headerValueStyle.Render(targetVal)

	tokenVal := "(无)"
	if m.token != "" {
		if len(m.token) > 8 {
			tokenVal = m.token[:4] + "..." + m.token[len(m.token)-4:]
		} else {
			tokenVal = m.token
		}
	}
	tokenPart := headerLabelStyle.Render("token:") + headerValueStyle.Render(tokenVal)

	tlsVal := "OFF"
	if m.useTLS {
		tlsVal = "ON"
	}
	tlsPart := headerLabelStyle.Render("TLS:") + headerValueStyle.Render(tlsVal)

	statusVal := statusIdleStyle.Render("空闲")
	if m.scanning {
		pct := 0
		if m.totalNodes > 0 {
			pct = m.doneNodes * 100 / m.totalNodes
		}
		elapsed := time.Since(m.scanStart).Round(time.Second)
		statusVal = statusScanningStyle.Render(fmt.Sprintf("扫描中 %d%% %s", pct, elapsed))
	} else if m.scanError {
		statusVal = statusErrorStyle.Render("错误")
	}

	content := fmt.Sprintf("%s  %s  %s  %s  %s", title, targetPart, tokenPart, tlsPart, statusVal)

	return headerStyle.Width(width).Render(content)
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
