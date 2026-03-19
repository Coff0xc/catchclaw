package tui

import "github.com/charmbracelet/bubbles/key"

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍KeyMap defines all TUI keybindings.
type KeyMap struct {
	Tab      key.Binding
	ShiftTab key.Binding
	Up       key.Binding
	Down     key.Binding
	Enter    key.Binding
	Slash    key.Binding
	Escape   key.Binding
	Sort     key.Binding
	Export   key.Binding
	Cancel   key.Binding
	Quit     key.Binding
	Help     key.Binding
	Top      key.Binding
	Bottom   key.Binding
}

// DefaultKeyMap returns the default keybinding set.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "下一面板"),
		),
		ShiftTab: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("S-tab", "上一面板"),
		),
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/↑", "上滚"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/↓", "下滚"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "执行/详情"),
		),
		Slash: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "命令"),
		),
		Escape: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "取消聚焦"),
		),
		Sort: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "排序"),
		),
		Export: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "导出"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("ctrl+x"),
			key.WithHelp("C-x", "取消扫描"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "退出"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "帮助"),
		),
		Top: key.NewBinding(
			key.WithKeys("g"),
			key.WithHelp("g", "顶部"),
		),
		Bottom: key.NewBinding(
			key.WithKeys("G"),
			key.WithHelp("G", "底部"),
		),
	}
}

// ShortHelp returns bindings for the compact help bar.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Slash, k.Sort, k.Export, k.Cancel, k.Quit}
}

// FullHelp returns all key bindings grouped.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Tab, k.ShiftTab, k.Slash, k.Escape},
		{k.Up, k.Down, k.Top, k.Bottom},
		{k.Sort, k.Export, k.Enter},
		{k.Cancel, k.Quit, k.Help},
	}
}
