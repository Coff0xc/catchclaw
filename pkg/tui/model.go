package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Panel identifies which panel is active.
type Panel int

const (
	PanelProgress Panel = iota
	PanelFindings
	PanelLog
	PanelInput
)

const (
	Version   = "4.1.0"
	minWidth  = 80
	minHeight = 24
)

// Model is the top-level Bubble Tea model.
type Model struct {
	width  int
	height int

	activePanel Panel
	keys        KeyMap

	// Bubbles components
	spinner     spinner.Model
	progressBar progress.Model
	logViewport viewport.Model
	cmdInput    textinput.Model

	// Scan state
	target     utils.Target
	token      string
	useTLS     bool
	timeout    time.Duration
	scanning   bool
	cancelScan context.CancelFunc

	// Data
	findings       []utils.Finding
	nodeStatus     []NodeStatus
	totalNodes     int
	doneNodes      int
	logLines       []string
	sortMode       SortMode
	findingsScroll int
	findingsCursor int
	progressScroll int

	// Channels
	progressCh chan concurrent.Progress
	logCh      chan string

	// Results
	lastResults []*utils.ScanResult
	scanStart   time.Time

	// Input history
	cmdHistory []string
	historyIdx int

	// Misc
	ready     bool
	showHelp  bool // toggle full help overlay
	scanError bool // last scan ended with error
}

// NewModel creates an initialized TUI model.
func NewModel(target utils.Target, token string, useTLS bool, timeout time.Duration) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorYellow)

	m := Model{
		activePanel: PanelInput,
		keys:        DefaultKeyMap(),
		spinner:     s,
		progressBar: newProgressBar(),
		logViewport: newLogViewport(80, 10),
		cmdInput:    newCmdInput(),
		target:      target,
		token:       token,
		useTLS:      useTLS,
		timeout:     timeout,
		sortMode:    SortBySeverity,
	}

	// Welcome guide
	welcome := []string{
		"🦞 LobsterGuard v" + Version + " — AI 编程平台安全评估工具",
		"",
		"快速开始: scan <host:port>            完整扫描",
		"          scan <host:port> --token x   带认证扫描",
		"          help                         查看所有命令",
	}
	for _, line := range welcome {
		m.logLines = append(m.logLines, line)
	}
	m.logViewport.SetContent(strings.Join(m.logLines, "\n"))

	return m
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		textinput.Blink,
		tea.EnterAltScreen,
	)
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		// Resize progress bar
		leftW := m.leftWidth()
		m.progressBar.Width = leftW - 6
		return m, nil

	case tea.KeyMsg:
		if m.showHelp {
			// Any key dismisses help overlay
			m.showHelp = false
			return m, nil
		}
		return m.handleKey(msg)

	case tea.MouseMsg:
		if msg.Action == tea.MouseActionPress {
			switch msg.Button {
			case tea.MouseButtonWheelUp:
				return m.scrollUp(), nil
			case tea.MouseButtonWheelDown:
				return m.scrollDown(), nil
			}
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case progress.FrameMsg:
		model, cmd := m.progressBar.Update(msg)
		m.progressBar = model.(progress.Model)
		cmds = append(cmds, cmd)

	case ProgressMsg:
		m.handleProgress(concurrent.Progress(msg))
		// Re-subscribe
		if m.progressCh != nil {
			cmds = append(cmds, waitForProgress(m.progressCh))
		}

	case LogLineMsg:
		ts := time.Now().Format("15:04:05")
		appendLog(&m, fmt.Sprintf("[%s] %s", ts, string(msg)))
		// Re-subscribe
		if m.logCh != nil {
			cmds = append(cmds, waitForLog(m.logCh))
		}

	case ScanStartedMsg:
		m.totalNodes = msg.Total
		m.doneNodes = 0

	case ScanCompleteMsg:
		m.scanning = false
		m.cancelScan = nil
		// Merge findings
		if msg.Findings != nil {
			m.findings = append(m.findings, msg.Findings...)
		}
		// Update all pending nodes to done
		for i := range m.nodeStatus {
			if m.nodeStatus[i].Status == "pending" || m.nodeStatus[i].Status == "running" {
				m.nodeStatus[i].Status = "done"
			}
		}
		m.doneNodes = m.totalNodes
		// Prominent scan-complete banner
		appendLog(&m, "")
		appendLog(&m, "════════════════════════════════════════")
		if len(m.findings) > 0 {
			appendLog(&m, fmt.Sprintf("🔴 扫描完成: 发现 %d 个安全问题! 耗时 %s", len(m.findings), msg.Elapsed))
		} else {
			appendLog(&m, fmt.Sprintf("✅ 扫描完成: 未发现安全问题。耗时 %s", msg.Elapsed))
		}
		appendLog(&m, "════════════════════════════════════════")

	case ScanErrorMsg:
		m.scanning = false
		m.scanError = true
		m.cancelScan = nil
		appendLog(&m, fmt.Sprintf("[!] 扫描错误: %v", msg.Err))

	case CmdResultMsg:
		if msg.IsErr {
			appendLog(&m, fmt.Sprintf("[!] %s", msg.Output))
		} else {
			appendLog(&m, msg.Output)
		}

	case FindingMsg:
		m.findings = append(m.findings, utils.Finding(msg))
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model.
func (m Model) View() string {
	if !m.ready {
		return "初始化中..."
	}
	if m.width < minWidth || m.height < minHeight {
		return renderMinSizeWarning(m.width, m.height)
	}

	// Help overlay on top — early return
	if m.showHelp {
		return renderHelpOverlay(m.keys, m.width, m.height)
	}

	// Layout: header(2) + upper panels + lower panel + input(3) + help(1)
	fixedH := 6 // header(2) + input(3) + help(1)
	remainH := m.height - fixedH
	if remainH < 6 {
		remainH = 6
	}
	upperH := remainH * 45 / 100
	if upperH < 5 {
		upperH = 5
	}
	lowerH := remainH - upperH
	if lowerH < 3 {
		lowerH = 3
	}

	leftW := m.leftWidth()
	rightW := m.width - leftW

	header := renderHeader(&m, m.width)
	progressPanel := renderProgress(&m, leftW, upperH, m.activePanel == PanelProgress)
	findingsPanel := renderFindings(&m, rightW, upperH, m.activePanel == PanelFindings)
	upperRow := lipgloss.JoinHorizontal(lipgloss.Top, progressPanel, findingsPanel)
	logPanel := renderLogView(&m, m.width, lowerH, m.activePanel == PanelLog)
	input := renderInput(&m, m.width)
	help := renderHelpBar(&m, m.width)

	view := lipgloss.JoinVertical(lipgloss.Left,
		header, upperRow, logPanel, input, help,
	)

	// Hard clamp to terminal size — Bubble Tea adds a trailing newline,
	// so we output exactly (height-1) lines to prevent scroll.
	placed := lipgloss.Place(m.width, m.height-1, lipgloss.Left, lipgloss.Top, view)
	lines := strings.Split(placed, "\n")
	if len(lines) > m.height-1 {
		lines = lines[:m.height-1]
	}
	return strings.Join(lines, "\n")
}

// --- Key handling ---

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// When input is focused, only handle escape and enter specially
	if m.activePanel == PanelInput && m.cmdInput.Focused() {
		switch msg.String() {
		case "esc":
			m.cmdInput.Blur()
			m.activePanel = PanelLog
			return m, nil
		case "enter":
			val := m.cmdInput.Value()
			m.cmdInput.SetValue("")
			if strings.TrimSpace(val) == "" {
				return m, nil // ignore empty enter
			}
			cmd := parseCommand(&m, val)
			var cmds []tea.Cmd
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			if m.scanning && m.progressCh != nil {
				cmds = append(cmds, waitForProgress(m.progressCh))
				cmds = append(cmds, waitForLog(m.logCh))
			}
			return m, tea.Batch(cmds...)
		case "tab":
			val := m.cmdInput.Value()
			if completed := completeCommand(val); completed != "" {
				m.cmdInput.SetValue(completed)
				m.cmdInput.CursorEnd()
			}
			return m, nil
		case "up":
			// Command history navigation
			if m.historyIdx > 0 {
				m.historyIdx--
				m.cmdInput.SetValue(m.cmdHistory[m.historyIdx])
			}
			return m, nil
		case "down":
			if m.historyIdx < len(m.cmdHistory)-1 {
				m.historyIdx++
				m.cmdInput.SetValue(m.cmdHistory[m.historyIdx])
			} else {
				m.historyIdx = len(m.cmdHistory)
				m.cmdInput.SetValue("")
			}
			return m, nil
		default:
			var cmd tea.Cmd
			m.cmdInput, cmd = m.cmdInput.Update(msg)
			return m, cmd
		}
	}

	// Global keys when input is not focused
	switch {
	case msg.String() == "q" || msg.String() == "ctrl+c":
		if m.scanning && m.cancelScan != nil {
			m.cancelScan()
		}
		return m, tea.Quit

	case msg.String() == "?":
		m.showHelp = !m.showHelp
		return m, nil

	case msg.String() == "1":
		m.activePanel = PanelProgress
		m.cmdInput.Blur()
		return m, nil
	case msg.String() == "2":
		m.activePanel = PanelFindings
		m.cmdInput.Blur()
		return m, nil
	case msg.String() == "3":
		m.activePanel = PanelLog
		m.cmdInput.Blur()
		return m, nil
	case msg.String() == "4":
		m.activePanel = PanelInput
		m.cmdInput.Focus()
		return m, nil

	case msg.String() == "tab":
		m.activePanel = (m.activePanel + 1) % 4
		if m.activePanel == PanelInput {
			m.cmdInput.Focus()
		} else {
			m.cmdInput.Blur()
		}
		return m, nil

	case msg.String() == "shift+tab":
		m.activePanel = (m.activePanel + 3) % 4 // -1 mod 4
		if m.activePanel == PanelInput {
			m.cmdInput.Focus()
		} else {
			m.cmdInput.Blur()
		}
		return m, nil

	case msg.String() == "/":
		m.activePanel = PanelInput
		m.cmdInput.Focus()
		return m, nil

	case msg.String() == "ctrl+x":
		if m.scanning && m.cancelScan != nil {
			m.cancelScan()
			appendLog(&m, "[!] Ctrl+X 取消扫描")
		}
		return m, nil

	case msg.String() == "s":
		if m.activePanel == PanelFindings {
			m.sortMode = m.sortMode.Next()
			appendLog(&m, fmt.Sprintf("[*] 排序: %s", m.sortMode))
		}
		return m, nil

	case msg.String() == "e":
		if len(m.findings) > 0 {
			return m, exportFindings(&m, "lobster-report.json")
		}
		return m, nil

	case msg.String() == "j", msg.String() == "down":
		return m.scrollDown(), nil

	case msg.String() == "k", msg.String() == "up":
		return m.scrollUp(), nil

	case msg.String() == "ctrl+d":
		return m.scrollPageDown(), nil

	case msg.String() == "ctrl+u":
		return m.scrollPageUp(), nil

	case msg.String() == "G":
		switch m.activePanel {
		case PanelLog:
			m.logViewport.GotoBottom()
		case PanelProgress:
			if len(m.nodeStatus) > 0 {
				m.progressScroll = len(m.nodeStatus) - 1
			}
		case PanelFindings:
			if len(m.findings) > 0 {
				m.findingsScroll = len(m.findings) - 1
				m.findingsCursor = 0
			}
		}
		return m, nil

	case msg.String() == "g":
		switch m.activePanel {
		case PanelLog:
			m.logViewport.GotoTop()
		case PanelProgress:
			m.progressScroll = 0
		case PanelFindings:
			m.findingsScroll = 0
			m.findingsCursor = 0
		}
		return m, nil

	case msg.String() == "enter":
		if m.activePanel == PanelFindings && len(m.findings) > 0 {
			idx := m.findingsScroll + m.findingsCursor
			if idx >= 0 && idx < len(m.findings) {
				f := m.findings[idx]
				appendLog(&m, fmt.Sprintf("─── %s [%s] ───", f.Title, f.Severity))
				appendLog(&m, fmt.Sprintf("模块: %s", f.Module))
				appendLog(&m, fmt.Sprintf("描述: %s", f.Description))
				if f.Evidence != "" {
					appendLog(&m, fmt.Sprintf("证据: %s", f.Evidence))
				}
				if f.Remediation != "" {
					appendLog(&m, fmt.Sprintf("修复建议: %s", f.Remediation))
				}
			}
		}
		return m, nil
	}

	return m, nil
}

func (m Model) scrollDown() Model {
	switch m.activePanel {
	case PanelProgress:
		if m.progressScroll < len(m.nodeStatus)-1 {
			m.progressScroll++
		}
	case PanelFindings:
		upperH := (m.height - 4) * 45 / 100
		maxVisible := upperH - 5
		if maxVisible < 1 {
			maxVisible = 1
		}
		if m.findingsCursor < maxVisible-1 && m.findingsCursor < len(m.findings)-1 {
			m.findingsCursor++
		} else if m.findingsScroll+maxVisible < len(m.findings) {
			m.findingsScroll++
		}
	case PanelLog:
		m.logViewport.ScrollDown(1)
	}
	return m
}

func (m Model) scrollUp() Model {
	switch m.activePanel {
	case PanelProgress:
		if m.progressScroll > 0 {
			m.progressScroll--
		}
	case PanelFindings:
		if m.findingsCursor > 0 {
			m.findingsCursor--
		} else if m.findingsScroll > 0 {
			m.findingsScroll--
		}
	case PanelLog:
		m.logViewport.ScrollUp(1)
	}
	return m
}

const pageScrollLines = 10

func (m Model) scrollPageDown() Model {
	for i := 0; i < pageScrollLines; i++ {
		m = m.scrollDown()
	}
	return m
}

func (m Model) scrollPageUp() Model {
	for i := 0; i < pageScrollLines; i++ {
		m = m.scrollUp()
	}
	return m
}

// --- Progress handling ---

func (m *Model) handleProgress(p concurrent.Progress) {
	// Update or add node status
	found := false
	for i := range m.nodeStatus {
		if m.nodeStatus[i].ID == p.TaskID {
			m.nodeStatus[i].Status = p.Status
			if p.Elapsed > 0 {
				m.nodeStatus[i].Elapsed = p.Elapsed.Round(time.Millisecond).String()
			}
			found = true
			break
		}
	}
	if !found {
		m.nodeStatus = append(m.nodeStatus, NodeStatus{
			ID:     p.TaskID,
			Name:   p.Name,
			Status: p.Status,
		})
		m.totalNodes = len(m.nodeStatus)
	}

	// Count done
	if p.Status == "done" || p.Status == "error" {
		done := 0
		for _, ns := range m.nodeStatus {
			if ns.Status == "done" || ns.Status == "error" || ns.Status == "skip" {
				done++
			}
		}
		m.doneNodes = done
	}

	// Collect findings from progress
	if p.Finding != nil {
		m.findings = append(m.findings, *p.Finding)
	}
}

// --- Helpers ---

func (m Model) leftWidth() int {
	w := m.width * 55 / 100
	if w < 30 {
		w = 30
	}
	return w
}

// Run starts the TUI application.
func Run(target utils.Target, token string, useTLS bool, timeout time.Duration) error {
	model := NewModel(target, token, useTLS, timeout)
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}
