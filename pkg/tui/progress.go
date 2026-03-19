package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/lipgloss"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍NodeStatus tracks per-chain node execution state.
type NodeStatus struct {
	ID      int
	Name    string
	Status  string // "pending", "running", "done", "error", "skip"
	Elapsed string
}

// renderProgress produces the chain progress panel.
func renderProgress(m *Model, width, height int, active bool) string {
	titleStyle := progressTitleStyle
	if active {
		titleStyle = titleStyle.Foreground(colorActiveBorder)
	}
	title := titleStyle.Render(fmt.Sprintf(" 攻击链进度 [%d/%d] ", m.doneNodes, m.totalNodes))

	// Compute inner dimensions (border takes 2 cols and 2 rows)
	innerW := width - 4
	if innerW < 10 {
		innerW = 10
	}
	innerH := height - 4 // title + progress bar + borders
	if innerH < 2 {
		innerH = 2
	}

	// Build node list with scrolling
	var lines []string
	startIdx := 0
	maxVisible := innerH - 2 // reserve 2 lines for progress bar
	if maxVisible < 1 {
		maxVisible = 1
	}

	// Auto-scroll to show currently running node
	runningIdx := -1
	for i, ns := range m.nodeStatus {
		if ns.Status == "running" {
			runningIdx = i
			break
		}
	}
	if runningIdx >= 0 && runningIdx >= maxVisible {
		startIdx = runningIdx - maxVisible/2
	}
	if m.activePanel == PanelProgress {
		// Use manual scroll position
		if m.progressScroll > 0 {
			startIdx = m.progressScroll
		}
	}
	if startIdx < 0 {
		startIdx = 0
	}
	if startIdx+maxVisible > len(m.nodeStatus) {
		startIdx = len(m.nodeStatus) - maxVisible
		if startIdx < 0 {
			startIdx = 0
		}
	}

	endIdx := startIdx + maxVisible
	if endIdx > len(m.nodeStatus) {
		endIdx = len(m.nodeStatus)
	}

	for i := startIdx; i < endIdx; i++ {
		ns := m.nodeStatus[i]
		var icon string
		var style lipgloss.Style
		switch ns.Status {
		case "done":
			icon = "✓"
			style = nodeDoneStyle
		case "running":
			icon = "▸"
			style = nodeRunningStyle
		case "error":
			icon = "✗"
			style = nodeErrorStyle
		case "skip":
			icon = "~"
			style = nodePendingStyle
		default:
			icon = "◦"
			style = nodePendingStyle
		}

		elapsed := ns.Elapsed
		if ns.Status == "running" {
			elapsed = "..."
		} else if ns.Status == "pending" {
			elapsed = ""
		}

		name := ns.Name
		maxNameLen := innerW - 16
		if maxNameLen < 8 {
			maxNameLen = 8
		}
		if len(name) > maxNameLen {
			name = name[:maxNameLen-1] + "…"
		}

		line := style.Render(fmt.Sprintf(" %s #%02d %-*s %5s", icon, ns.ID, maxNameLen, name, elapsed))
		lines = append(lines, line)
	}

	// Pad empty lines
	for len(lines) < maxVisible {
		lines = append(lines, strings.Repeat(" ", innerW))
	}

	// Progress bar with percentage text
	pct := 0.0
	if m.totalNodes > 0 {
		pct = float64(m.doneNodes) / float64(m.totalNodes)
	}
	bar := m.progressBar.ViewAs(pct)
	pctText := lipgloss.NewStyle().Foreground(colorPurple).Bold(true).
		Render(fmt.Sprintf(" [%d/%d %d%%]", m.doneNodes, m.totalNodes, int(pct*100)))

	nodeList := strings.Join(lines, "\n")
	content := title + "\n" + nodeList + "\n" + bar + pctText

	return panelStyle(active, width-2, height-2).Render(content)
}

// newProgressBar creates a configured progress bar.
func newProgressBar() progress.Model {
	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithoutPercentage(),
	)
	p.PercentageStyle = lipgloss.NewStyle().Foreground(colorPurple)
	return p
}
