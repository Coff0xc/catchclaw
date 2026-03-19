package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/report"
	"github.com/coff0xc/lobster-guard/pkg/scan"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍startScan begins a scan in a background goroutine, returning a tea.Cmd.
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
		// Enable quiet mode to suppress engine/exploit direct prints
		// NOTE: Do NOT redirect os.Stdout here — Bubble Tea uses it for rendering
		concurrent.QuietMode = true
		exploit.QuietMode = true

		cfg := scan.DefaultScanConfig()
		cfg.Token = token
		cfg.Timeout = timeout
		cfg.NoBrute = true // TUI doesn't do brute force by default

		var findings []utils.Finding

		switch mode {
		case "scan":
			findings = scan.RunFullScan(ctx, target, cfg, progressCh, logCh)
		case "exploit":
			findings = scan.RunExploitScan(ctx, target, cfg, progressCh, logCh)
		case "fingerprint":
			findings = scan.RunFingerprint(target, cfg, logCh)
		case "auth":
			findings = scan.RunAuthCheck(target, cfg, logCh)
		case "recon":
			findings = scan.RunReconCheck(target, cfg, logCh)
		case "audit":
			findings = scan.RunAuditCheck(target, cfg, logCh)
		}

		concurrent.QuietMode = false
		exploit.QuietMode = false

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
		concurrent.QuietMode = true
		exploit.QuietMode = true

		cfg := scan.DefaultScanConfig()
		cfg.Token = token
		cfg.Timeout = timeout
		cfg.ChainID = chainID

		findings := scan.RunExploitScan(ctx, target, cfg, progressCh, logCh)

		concurrent.QuietMode = false
		exploit.QuietMode = false
		close(progressCh)
		close(logCh)

		elapsed := time.Since(m.scanStart).Round(time.Millisecond).String()
		return ScanCompleteMsg{Findings: findings, Elapsed: elapsed}
	}
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
