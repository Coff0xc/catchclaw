package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/coff0xc/lobster-guard/pkg/audit"
	"github.com/coff0xc/lobster-guard/pkg/auth"
	"github.com/coff0xc/lobster-guard/pkg/chain"
	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/recon"
	"github.com/coff0xc/lobster-guard/pkg/report"
	"github.com/coff0xc/lobster-guard/pkg/scanner"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// startScan begins a scan in a background goroutine, returning a tea.Cmd.
func startScan(m *Model, mode string) tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelScan = cancel
	m.scanning = true
	m.scanError = false
	m.scanStart = time.Now()

	// Reset state
	m.findings = nil
	m.doneNodes = 0

	progressCh := make(chan concurrent.Progress, 100)
	logCh := make(chan string, 200)
	m.progressCh = progressCh
	m.logCh = logCh

	target := m.target
	token := m.token
	timeout := m.timeout

	appendLog(m, fmt.Sprintf("[*] 开始 %s 扫描 %s ...", mode, target.String()))

	return func() tea.Msg {
		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Enable quiet mode to suppress engine/exploit direct prints
		concurrent.QuietMode = true
		exploit.QuietMode = true

		go func() {
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				line := scanner.Text()
				select {
				case logCh <- line:
				default:
				}
			}
		}()

		var findings []utils.Finding

		switch mode {
		case "scan":
			findings = runFullScan(ctx, target, token, timeout, progressCh, logCh)
		case "exploit":
			findings = runExploitScan(ctx, target, token, timeout, progressCh, logCh)
		case "fingerprint":
			findings = runFingerprint(target, timeout, logCh)
		case "auth":
			findings = runAuthCheck(target, timeout, logCh)
		case "recon":
			findings = runReconCheck(target, token, timeout, logCh)
		case "audit":
			findings = runAuditCheck(target, token, timeout, logCh)
		}

		// Restore stdout
		w.Close()
		os.Stdout = oldStdout
		concurrent.QuietMode = false
		exploit.QuietMode = false
		io.Copy(io.Discard, r) // drain remaining
		r.Close()

		close(progressCh)
		close(logCh)

		elapsed := time.Since(m.scanStart).Round(time.Millisecond).String()
		return ScanCompleteMsg{Findings: findings, Elapsed: elapsed}
	}
}

// startSingleChain runs a single exploit chain by ID.
func startSingleChain(m *Model, chainID int) tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelScan = cancel
	m.scanning = true
	m.scanError = false
	m.scanStart = time.Now()
	m.findings = nil
	m.doneNodes = 0

	progressCh := make(chan concurrent.Progress, 100)
	logCh := make(chan string, 200)
	m.progressCh = progressCh
	m.logCh = logCh

	target := m.target
	token := m.token
	timeout := m.timeout

	// Set up single node status
	m.totalNodes = 1
	m.nodeStatus = []NodeStatus{{ID: chainID, Name: fmt.Sprintf("Chain #%d", chainID), Status: "pending"}}

	appendLog(m, fmt.Sprintf("[*] 执行攻击链 #%d 目标 %s ...", chainID, target.String()))

	return func() tea.Msg {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		concurrent.QuietMode = true
		exploit.QuietMode = true

		go func() {
			sc := bufio.NewScanner(r)
			for sc.Scan() {
				select {
				case logCh <- sc.Text():
				default:
				}
			}
		}()

		cfg := chain.ChainConfig{Token: token, Timeout: timeout}
		dag := chain.BuildFullDAG(5, false)

		select {
		case <-ctx.Done():
			// cancelled
		default:
		}

		findings := dag.ExecuteSingle(target, cfg, chainID)

		w.Close()
		os.Stdout = oldStdout
		concurrent.QuietMode = false
		exploit.QuietMode = false
		io.Copy(io.Discard, r)
		r.Close()
		close(progressCh)
		close(logCh)

		elapsed := time.Since(m.scanStart).Round(time.Millisecond).String()
		return ScanCompleteMsg{Findings: findings, Elapsed: elapsed}
	}
}

// --- Scan mode implementations ---

func runFullScan(ctx context.Context, target utils.Target, token string, timeout time.Duration, progressCh chan concurrent.Progress, logCh chan string) []utils.Finding {
	var all []utils.Finding

	// 1. Fingerprint
	sendLog(logCh, "[*] 阶段 1: 指纹识别...")
	fpResult, fpFindings := scanner.Fingerprint(target, timeout)
	all = append(all, fpFindings...)

	if !fpResult.IsOpenClaw {
		sendLog(logCh, fmt.Sprintf("[*] %s 不是 OpenClaw 平台，终止扫描", target.String()))
		return all
	}
	sendLog(logCh, fmt.Sprintf("[+] 检测到 OpenClaw: %s", fpResult.Version))

	// 2. Auth check
	if ctx.Err() != nil {
		return all
	}
	sendLog(logCh, "[*] 阶段 2: 认证检测...")
	authFindings := auth.NoAuthCheck(target, timeout)
	all = append(all, authFindings...)

	// 3. Recon
	if ctx.Err() != nil {
		return all
	}
	sendLog(logCh, "[*] 阶段 3: 信息收集...")
	_, reconF1 := recon.VersionDetect(target, timeout)
	all = append(all, reconF1...)
	_, reconF2 := recon.EnumEndpoints(target, token, timeout)
	all = append(all, reconF2...)
	_, reconF3 := recon.EnumWSMethods(target, token, timeout)
	all = append(all, reconF3...)

	// 4. Audit
	if ctx.Err() != nil {
		return all
	}
	if token != "" {
		sendLog(logCh, "[*] 阶段 4: 配置审计...")
		auditFindings := audit.RunAudit(target, audit.AuditConfig{Token: token, Timeout: timeout})
		all = append(all, auditFindings...)
	}

	// 5. DAG exploit
	if ctx.Err() != nil {
		return all
	}
	sendLog(logCh, "[*] 阶段 5: DAG 攻击链...")
	exploitFindings := runExploitWithEngine(ctx, target, token, timeout, progressCh, logCh)
	all = append(all, exploitFindings...)

	return all
}

func runExploitScan(ctx context.Context, target utils.Target, token string, timeout time.Duration, progressCh chan concurrent.Progress, logCh chan string) []utils.Finding {
	sendLog(logCh, "[*] 执行 DAG 攻击链...")
	return runExploitWithEngine(ctx, target, token, timeout, progressCh, logCh)
}

func runExploitWithEngine(ctx context.Context, target utils.Target, token string, timeout time.Duration, progressCh chan concurrent.Progress, logCh chan string) []utils.Finding {
	engine := concurrent.NewEngine(10, 0)
	engine.Timeout = timeout
	engine.ProgressChan = progressCh

	dag := chain.BuildFullDAG(10, false)
	cfg := chain.ChainConfig{Token: token, Timeout: timeout}

	var tasks []concurrent.ScanTask
	for _, node := range dag.Nodes {
		n := node
		tasks = append(tasks, concurrent.ScanTask{
			ID:       n.ID,
			Name:     n.Name,
			Target:   target,
			Token:    token,
			ChainID:  n.ID,
			Priority: 1,
			Execute: func(t utils.Target, tk string) []utils.Finding {
				return n.Execute(t, cfg)
			},
		})
	}

	// Report total to UI
	sendLog(logCh, fmt.Sprintf("[*] DAG: %d 条攻击链已入队", len(tasks)))

	findings := engine.RunWithContext(ctx, tasks, func(p concurrent.Progress) {
		select {
		case progressCh <- p:
		default:
		}
	})

	return findings
}

func runFingerprint(target utils.Target, timeout time.Duration, logCh chan string) []utils.Finding {
	sendLog(logCh, "[*] 执行指纹识别...")
	_, findings := scanner.Fingerprint(target, timeout)
	return findings
}

func runAuthCheck(target utils.Target, timeout time.Duration, logCh chan string) []utils.Finding {
	sendLog(logCh, "[*] 执行认证检测...")
	return auth.NoAuthCheck(target, timeout)
}

func runReconCheck(target utils.Target, token string, timeout time.Duration, logCh chan string) []utils.Finding {
	sendLog(logCh, "[*] 执行信息收集...")
	var all []utils.Finding
	_, f1 := recon.VersionDetect(target, timeout)
	all = append(all, f1...)
	_, f2 := recon.EnumEndpoints(target, token, timeout)
	all = append(all, f2...)
	_, f3 := recon.EnumWSMethods(target, token, timeout)
	all = append(all, f3...)
	return all
}

func runAuditCheck(target utils.Target, token string, timeout time.Duration, logCh chan string) []utils.Finding {
	if token == "" {
		sendLog(logCh, "[!] 配置审计需要 Token")
		return nil
	}
	sendLog(logCh, "[*] 执行配置审计...")
	return audit.RunAudit(target, audit.AuditConfig{Token: token, Timeout: timeout})
}

// exportFindings writes findings to a report file.
func exportFindings(m *Model, path string) tea.Cmd {
	result := utils.NewScanResult(m.target)
	for _, f := range m.findings {
		result.Add(f)
	}
	result.Done()
	results := []*utils.ScanResult{result}

	return func() tea.Msg {
		err := report.WriteReport(results, path)
		if err != nil {
			return CmdResultMsg{Output: fmt.Sprintf("导出失败: %v", err), IsErr: true}
		}
		return CmdResultMsg{Output: fmt.Sprintf("已导出 %d 个发现至 %s", len(m.findings), path)}
	}
}

func sendLog(ch chan string, msg string) {
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", ts, msg)
	select {
	case ch <- line:
	default:
	}
}

// waitForProgress returns a tea.Cmd that waits for the next progress message.
func waitForProgress(ch <-chan concurrent.Progress) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return nil
		}
		return ProgressMsg(p)
	}
}

// waitForLog returns a tea.Cmd that waits for the next log line.
func waitForLog(ch <-chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return nil
		}
		return LogLineMsg(line)
	}
}
