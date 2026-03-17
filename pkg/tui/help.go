package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/lipgloss"
)

// renderHelpBar produces a context-aware one-line help bar.
func renderHelpBar(m *Model, width int) string {
	var bindings []key.Binding

	if m.activePanel == PanelInput && m.cmdInput.Focused() {
		// Input-specific hints
		bindings = []key.Binding{
			key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "补全")),
			key.NewBinding(key.WithKeys("up"), key.WithHelp("↑/↓", "历史")),
			key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "退出输入")),
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "执行")),
		}
	} else {
		bindings = []key.Binding{
			m.keys.Tab,
			key.NewBinding(key.WithKeys("1"), key.WithHelp("1-4", "面板")),
			m.keys.Slash,
			key.NewBinding(key.WithKeys("j"), key.WithHelp("j/k", "滚动")),
			key.NewBinding(key.WithKeys("ctrl+d"), key.WithHelp("C-d/u", "翻页")),
		}
		// Context-specific keys
		switch m.activePanel {
		case PanelFindings:
			bindings = append(bindings, m.keys.Sort, m.keys.Enter)
		case PanelLog:
			bindings = append(bindings, m.keys.Top, m.keys.Bottom)
		}
		if m.scanning {
			bindings = append(bindings, m.keys.Cancel)
		}
		if len(m.findings) > 0 {
			bindings = append(bindings, m.keys.Export)
		}
		bindings = append(bindings, m.keys.Help, m.keys.Quit)
	}

	return renderBindings(bindings, width)
}

func renderBindings(bindings []key.Binding, width int) string {
	var parts []string
	for _, b := range bindings {
		if !b.Enabled() {
			continue
		}
		k := helpKeyStyle.Render(b.Help().Key)
		d := helpDescStyle.Render(b.Help().Desc)
		parts = append(parts, k+helpSepStyle.Render(":")+d)
	}
	line := strings.Join(parts, helpSepStyle.Render("  "))
	return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(line)
}

// renderHelpOverlay produces a full-screen help overlay.
func renderHelpOverlay(keys KeyMap, width, height int) string {
	title := lipgloss.NewStyle().
		Foreground(colorPurple).Bold(true).
		Render("  快捷键帮助  ")

	groups := keys.FullHelp()
	groupNames := []string{"导航", "滚动", "操作", "系统"}

	var sections []string
	for i, group := range groups {
		header := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).
			Render(fmt.Sprintf("  %s", groupNames[i]))
		var lines []string
		lines = append(lines, header)
		for _, b := range group {
			k := helpKeyStyle.Render(fmt.Sprintf("  %-12s", b.Help().Key))
			d := helpDescStyle.Render(b.Help().Desc)
			lines = append(lines, k+d)
		}
		sections = append(sections, strings.Join(lines, "\n"))
	}

	// Extra keys not in FullHelp
	extra := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).
		Render("  扩展")
	extraLines := []string{
		extra,
		helpKeyStyle.Render("  1-4         ") + helpDescStyle.Render("直接跳转面板"),
		helpKeyStyle.Render("  C-d/C-u     ") + helpDescStyle.Render("半页滚动"),
		helpKeyStyle.Render("  tab(输入中) ") + helpDescStyle.Render("命令补全"),
		helpKeyStyle.Render("  ↑/↓(输入中) ") + helpDescStyle.Render("命令历史"),
	}
	sections = append(sections, strings.Join(extraLines, "\n"))

	body := strings.Join(sections, "\n\n")
	footer := helpDescStyle.Render("\n  按任意键关闭")

	content := title + "\n\n" + body + footer

	return lipgloss.NewStyle().
		Width(width).Height(height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(content)
}
