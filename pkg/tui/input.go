package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Available commands for tab completion.
var commandList = []string{
	"target", "token", "tls", "timeout",
	"scan", "exploit", "fingerprint", "auth", "recon", "audit",
	"cancel", "export", "clear", "status", "help",
}

// newCmdInput creates a configured text input.
func newCmdInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "输入命令..."
	ti.Prompt = "lobster🦞> "
	ti.PromptStyle = inputPromptStyle
	ti.TextStyle = inputStyle
	ti.CharLimit = 256
	ti.Focus()
	return ti
}

// renderInput produces the command input line with visual border.
func renderInput(m *Model, width int) string {
	promptW := lipgloss.Width(m.cmdInput.Prompt)
	m.cmdInput.Width = width - promptW - 4 // 4 = border padding
	if m.cmdInput.Width < 10 {
		m.cmdInput.Width = 10
	}
	style := inputBoxStyle
	if m.activePanel == PanelInput {
		style = inputBoxActiveStyle
	}
	return style.Width(width - 2).Render(m.cmdInput.View())
}

// completeCommand returns the first matching command for the given prefix.
func completeCommand(prefix string) string {
	if prefix == "" {
		return ""
	}
	prefix = strings.ToLower(prefix)
	for _, cmd := range commandList {
		if strings.HasPrefix(cmd, prefix) && cmd != prefix {
			return cmd
		}
	}
	return ""
}

// parseCommand interprets user input and returns a tea.Cmd.
func parseCommand(m *Model, raw string) tea.Cmd {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// Store in history
	m.cmdHistory = append(m.cmdHistory, raw)
	m.historyIdx = len(m.cmdHistory)

	parts := strings.Fields(raw)
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "target":
		return cmdTarget(m, args)
	case "token":
		return cmdToken(m, args)
	case "tls":
		return cmdTLS(m, args)
	case "timeout":
		return cmdTimeout(m, args)
	case "scan":
		// Support: scan <target> [--token x] [--tls]
		if len(args) > 0 {
			t, err := utils.ParseTarget(args[0])
			if err == nil {
				t.UseTLS = m.useTLS
				m.target = t
				appendLog(m, fmt.Sprintf("[*] 目标已设置: %s", t.String()))
			}
			for i := 1; i < len(args); i++ {
				switch args[i] {
				case "--token":
					if i+1 < len(args) {
						m.token = args[i+1]
						appendLog(m, "[*] Token 已更新")
						i++
					}
				case "--tls":
					m.useTLS = true
					m.target.UseTLS = true
				}
			}
		}
		return cmdScan(m)
	case "exploit":
		// Support: exploit <target> [chain_id]
		if len(args) > 0 {
			// First arg could be target or chain_id
			if _, err := strconv.Atoi(args[0]); err != nil {
				// It's a target
				t, err := utils.ParseTarget(args[0])
				if err == nil {
					t.UseTLS = m.useTLS
					m.target = t
					appendLog(m, fmt.Sprintf("[*] 目标已设置: %s", t.String()))
				}
				args = args[1:]
			}
		}
		return cmdExploit(m, args)
	case "fingerprint":
		return cmdModule(m, "fingerprint")
	case "auth":
		return cmdModule(m, "auth")
	case "recon":
		return cmdModule(m, "recon")
	case "audit":
		return cmdModule(m, "audit")
	case "cancel":
		return cmdCancel(m)
	case "export":
		return cmdExport(m, args)
	case "clear":
		return cmdClear(m)
	case "status":
		return cmdStatus(m)
	case "help":
		return cmdHelp(m)
	default:
		return msgCmd(CmdResultMsg{Output: fmt.Sprintf("未知命令: %s，输入 'help' 查看帮助", cmd), IsErr: true})
	}
}

func cmdTarget(m *Model, args []string) tea.Cmd {
	if len(args) == 0 {
		if m.target.Host != "" {
			return msgCmd(CmdResultMsg{Output: fmt.Sprintf("当前目标: %s", m.target.String())})
		}
		return msgCmd(CmdResultMsg{Output: "用法: target <host:port>", IsErr: true})
	}
	t, err := utils.ParseTarget(args[0])
	if err != nil {
		return msgCmd(CmdResultMsg{Output: fmt.Sprintf("无效目标: %v", err), IsErr: true})
	}
	t.UseTLS = m.useTLS
	m.target = t
	appendLog(m, fmt.Sprintf("[*] 目标已设置: %s", t.String()))
	return msgCmd(CmdResultMsg{Output: fmt.Sprintf("目标: %s", t.String())})
}

func cmdToken(m *Model, args []string) tea.Cmd {
	if len(args) == 0 {
		return msgCmd(CmdResultMsg{Output: "用法: token <value>", IsErr: true})
	}
	m.token = args[0]
	appendLog(m, "[*] Token 已更新")
	return msgCmd(CmdResultMsg{Output: "Token 已设置"})
}

func cmdTLS(m *Model, args []string) tea.Cmd {
	if len(args) == 0 {
		return msgCmd(CmdResultMsg{Output: fmt.Sprintf("TLS: %v", m.useTLS)})
	}
	switch strings.ToLower(args[0]) {
	case "on", "true", "1":
		m.useTLS = true
		m.target.UseTLS = true
	case "off", "false", "0":
		m.useTLS = false
		m.target.UseTLS = false
	default:
		return msgCmd(CmdResultMsg{Output: "用法: tls on|off", IsErr: true})
	}
	appendLog(m, fmt.Sprintf("[*] TLS: %v", m.useTLS))
	return msgCmd(CmdResultMsg{Output: fmt.Sprintf("TLS: %v", m.useTLS)})
}

func cmdTimeout(m *Model, args []string) tea.Cmd {
	if len(args) == 0 {
		return msgCmd(CmdResultMsg{Output: fmt.Sprintf("Timeout: %v", m.timeout)})
	}
	sec, err := strconv.Atoi(args[0])
	if err != nil || sec <= 0 {
		return msgCmd(CmdResultMsg{Output: "用法: timeout <秒数>", IsErr: true})
	}
	m.timeout = time.Duration(sec) * time.Second
	return msgCmd(CmdResultMsg{Output: fmt.Sprintf("Timeout: %v", m.timeout)})
}

func cmdScan(m *Model) tea.Cmd {
	if m.target.Host == "" {
		return msgCmd(CmdResultMsg{Output: "请先设置目标: target <host:port>", IsErr: true})
	}
	if m.scanning {
		return msgCmd(CmdResultMsg{Output: "扫描已在运行，使用 'cancel' 停止", IsErr: true})
	}
	return startScan(m, "scan")
}

func cmdExploit(m *Model, args []string) tea.Cmd {
	if m.target.Host == "" {
		return msgCmd(CmdResultMsg{Output: "请先设置目标: target <host:port>", IsErr: true})
	}
	if m.scanning {
		return msgCmd(CmdResultMsg{Output: "扫描正在运行", IsErr: true})
	}
	if len(args) > 0 {
		chainID, err := strconv.Atoi(args[0])
		if err != nil {
			return msgCmd(CmdResultMsg{Output: "用法: exploit [chain_id]", IsErr: true})
		}
		return startSingleChain(m, chainID)
	}
	return startScan(m, "exploit")
}

func cmdModule(m *Model, module string) tea.Cmd {
	if m.target.Host == "" {
		return msgCmd(CmdResultMsg{Output: "请先设置目标: target <host:port>", IsErr: true})
	}
	if m.scanning {
		return msgCmd(CmdResultMsg{Output: "扫描正在运行", IsErr: true})
	}
	return startScan(m, module)
}

func cmdCancel(m *Model) tea.Cmd {
	if !m.scanning || m.cancelScan == nil {
		return msgCmd(CmdResultMsg{Output: "当前无扫描任务"})
	}
	m.cancelScan()
	appendLog(m, "[!] 用户取消扫描")
	return msgCmd(CmdResultMsg{Output: "扫描已取消"})
}

func cmdExport(m *Model, args []string) tea.Cmd {
	if len(m.findings) == 0 {
		return msgCmd(CmdResultMsg{Output: "无发现可导出", IsErr: true})
	}
	path := "lobster-report.json"
	if len(args) > 0 {
		path = args[0]
	}
	return exportFindings(m, path)
}

func cmdClear(m *Model) tea.Cmd {
	m.logLines = nil
	m.logViewport.SetContent("")
	return msgCmd(CmdResultMsg{Output: "日志已清空"})
}

func cmdStatus(m *Model) tea.Cmd {
	status := "空闲"
	if m.scanning {
		status = fmt.Sprintf("扫描中 (%d/%d)", m.doneNodes, m.totalNodes)
	}
	msg := fmt.Sprintf("状态: %s | 目标: %s | 发现: %d | TLS: %v | 超时: %v",
		status, m.target.String(), len(m.findings), m.useTLS, m.timeout)
	return msgCmd(CmdResultMsg{Output: msg})
}

func cmdHelp(_ *Model) tea.Cmd {
	help := `命令列表:
  target <host:port>   设置扫描目标
  token <value>        设置认证令牌
  tls on|off           切换 TLS 加密
  timeout <秒数>       设置超时时间
  scan                 完整流水线 (指纹+认证+DAG攻击链)
  exploit [chain_id]   DAG 攻击链
  fingerprint          仅平台指纹识别
  auth                 仅认证检测
  recon                仅信息收集
  audit                仅配置审计
  cancel               取消当前扫描
  export [路径]        导出报告 (.json/.html 自动识别)
  clear                清空日志
  status               显示状态
  help                 显示本帮助`
	return msgCmd(CmdResultMsg{Output: help})
}

// msgCmd wraps a message as a tea.Cmd.
func msgCmd(msg tea.Msg) tea.Cmd {
	return func() tea.Msg { return msg }
}
