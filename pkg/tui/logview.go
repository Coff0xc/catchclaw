package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
)

// renderLogView produces the log viewport panel.
func renderLogView(m *Model, width, height int, active bool) string {
	titleStyle := logTitleStyle
	if active {
		titleStyle = titleStyle.Foreground(colorActiveBorder)
	}
	title := titleStyle.Render(fmt.Sprintf(" 日志 (%d 行) ", len(m.logLines)))

	innerW := width - 4
	if innerW < 10 {
		innerW = 10
	}
	innerH := height - 3
	if innerH < 1 {
		innerH = 1
	}

	// Update viewport dimensions only — content is set in appendLog
	m.logViewport.Width = innerW
	m.logViewport.Height = innerH

	body := title + "\n" + m.logViewport.View()
	return panelStyle(active, width-2, height-2).Render(body)
}

// newLogViewport creates a configured viewport for log display.
func newLogViewport(width, height int) viewport.Model {
	vp := viewport.New(width, height)
	vp.SetContent("")
	return vp
}

// appendLog adds a line to the log buffer and auto-scrolls.
func appendLog(m *Model, line string) {
	const maxLogLines = 1000
	m.logLines = append(m.logLines, line)
	if len(m.logLines) > maxLogLines {
		m.logLines = m.logLines[len(m.logLines)-maxLogLines:]
	}
	// Set content first, then scroll — fixes GotoBottom on stale content
	m.logViewport.SetContent(strings.Join(m.logLines, "\n"))
	m.logViewport.GotoBottom()
}
