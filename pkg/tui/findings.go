package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍SortMode controls finding sort order.
type SortMode int

const (
	SortBySeverity SortMode = iota
	SortByModule
	SortByTime
)

func (s SortMode) String() string {
	switch s {
	case SortBySeverity:
		return "严重度"
	case SortByModule:
		return "模块"
	case SortByTime:
		return "时间"
	default:
		return "严重度"
	}
}

// NextSortMode cycles through sort modes.
func (s SortMode) Next() SortMode {
	return (s + 1) % 3
}

// renderFindings produces the findings table panel.
func renderFindings(m *Model, width, height int, active bool) string {
	count := len(m.findings)
	titleStyle := findingsTitleStyle
	if active {
		titleStyle = titleStyle.Foreground(colorActiveBorder)
	}

	// Title with severity counts
	titleText := fmt.Sprintf(" 漏洞发现 (%d) ", count)
	if count > 0 {
		titleText = fmt.Sprintf(" 漏洞发现 (%d)  %s ", count, severityCounts(m))
	}
	title := titleStyle.Render(titleText)

	innerW := width - 4
	if innerW < 10 {
		innerW = 10
	}
	innerH := height - 4
	if innerH < 2 {
		innerH = 2
	}

	if count == 0 {
		emptyMsg := lipgloss.NewStyle().Foreground(colorDim).Render("  暂无发现")
		content := title + "\n" + emptyMsg
		return panelStyle(active, width-2, height-2).Render(content)
	}

	// Sort findings
	sorted := make([]utils.Finding, len(m.findings))
	copy(sorted, m.findings)
	sortFindings(sorted, m.sortMode)

	// Column widths
	sevW := 9
	modW := innerW / 4
	if modW < 8 {
		modW = 8
	}
	titleW := innerW - sevW - modW - 8
	if titleW < 8 {
		titleW = 8
	}

	// Table header + separator (consume 2 lines)
	header := findingsHeaderStyle.Render(
		fmt.Sprintf(" %-*s│ %-*s│ %s", sevW, "SEV", modW+1, "MODULE", "TITLE"))
	sep := lipgloss.NewStyle().Foreground(colorDim).Render(
		" " + strings.Repeat("─", sevW) + "┼" + strings.Repeat("─", modW+1) + "┼" + strings.Repeat("─", titleW+2))

	// Build table rows with scrolling
	maxVisible := innerH - 3 // -1 title -2 header+sep
	if maxVisible < 1 {
		maxVisible = 1
	}

	startIdx := m.findingsScroll
	if startIdx < 0 {
		startIdx = 0
	}
	if startIdx+maxVisible > len(sorted) {
		startIdx = len(sorted) - maxVisible
		if startIdx < 0 {
			startIdx = 0
		}
	}
	endIdx := startIdx + maxVisible
	if endIdx > len(sorted) {
		endIdx = len(sorted)
	}

	var lines []string
	for i := startIdx; i < endIdx; i++ {
		f := sorted[i]
		sevStr := f.Severity.String()
		sevStyled := styleSeverity(sevStr, sevW)

		mod := f.Module
		if len(mod) > modW {
			mod = mod[:modW-1] + "…"
		}

		ttl := f.Title
		if len(ttl) > titleW {
			ttl = ttl[:titleW-1] + "…"
		}

		indicator := " "
		isSelected := active && i == m.findingsCursor+startIdx
		if isSelected {
			indicator = ">"
		}

		line := fmt.Sprintf("%s%s│ %-*s│ %s", indicator, sevStyled, modW+1, mod, ttl)
		if isSelected {
			line = findingsRowHighlight.Render(line)
		}
		lines = append(lines, line)
	}

	// Pad
	for len(lines) < maxVisible {
		lines = append(lines, strings.Repeat(" ", innerW))
	}

	content := title + "\n" + header + "\n" + sep + "\n" + strings.Join(lines, "\n")
	return panelStyle(active, width-2, height-2).Render(content)
}

// severityCounts returns a compact colored severity summary string.
func severityCounts(m *Model) string {
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

func styleSeverity(sev string, width int) string {
	padded := fmt.Sprintf("%-*s", width, sev)
	switch sev {
	case "CRITICAL":
		return findingCritStyle.Render(padded)
	case "HIGH":
		return findingHighStyle.Render(padded)
	case "MEDIUM":
		return findingMedStyle.Render(padded)
	case "LOW":
		return findingLowStyle.Render(padded)
	default:
		return findingInfoStyle.Render(padded)
	}
}

func sortFindings(findings []utils.Finding, mode SortMode) {
	switch mode {
	case SortBySeverity:
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Severity > findings[j].Severity // CRITICAL first
		})
	case SortByModule:
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Module < findings[j].Module
		})
	case SortByTime:
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Timestamp > findings[j].Timestamp // newest first
		})
	}
}
