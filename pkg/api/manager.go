package api

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/scan"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍ScanStatus 表示异步扫描的状态。
type ScanStatus struct {
	ID        string          `json:"id"`
	Target    string          `json:"target"`
	Mode      string          `json:"mode"`
	Status    string          `json:"status"` // "running", "completed", "cancelled", "error"
	StartTime string          `json:"start_time"`
	EndTime   string          `json:"end_time,omitempty"`
	Elapsed   string          `json:"elapsed,omitempty"`
	Findings  []utils.Finding `json:"findings"`
	Total     int             `json:"total_findings"`
	Logs      []string        `json:"logs,omitempty"`
}

type scanEntry struct {
	status ScanStatus
	cancel context.CancelFunc
	mu     sync.Mutex
}

// ScanManager 管理异步扫描生命周期。
type ScanManager struct {
	mu      sync.RWMutex
	entries map[string]*scanEntry
	counter int
}

// NewScanManager 创建扫描管理器。
func NewScanManager() *ScanManager {
	return &ScanManager{
		entries: make(map[string]*scanEntry),
	}
}

// Start 启动异步扫描并返回扫描 ID。
func (m *ScanManager) Start(target utils.Target, cfg scan.ScanConfig, mode string) string {
	m.mu.Lock()
	m.counter++
	id := fmt.Sprintf("scan-%d-%d", time.Now().Unix(), m.counter)
	ctx, cancel := context.WithCancel(context.Background())

	entry := &scanEntry{
		status: ScanStatus{
			ID:        id,
			Target:    target.String(),
			Mode:      mode,
			Status:    "running",
			StartTime: time.Now().UTC().Format(time.RFC3339),
			Findings:  []utils.Finding{},
			Logs:      []string{},
		},
		cancel: cancel,
	}
	m.entries[id] = entry
	m.mu.Unlock()

	progressCh := make(chan concurrent.Progress, 100)
	logCh := make(chan string, 200)

	// 后台消费日志通道
	go func() {
		for line := range logCh {
			entry.mu.Lock()
			entry.status.Logs = append(entry.status.Logs, line)
			entry.mu.Unlock()
		}
	}()

	// 后台消费进度通道（防止阻塞）
	go func() {
		for range progressCh {
		}
	}()

	// 后台执行扫描
	go func() {
		defer close(progressCh)
		defer close(logCh)

		start := time.Now()
		var findings []utils.Finding

		switch mode {
		case "fingerprint":
			findings = scan.RunFingerprint(target, cfg, logCh)
		case "auth":
			findings = scan.RunAuthCheck(target, cfg, logCh)
		case "recon":
			findings = scan.RunReconCheck(target, cfg, logCh)
		case "audit":
			findings = scan.RunAuditCheck(target, cfg, logCh)
		case "exploit":
			findings = scan.RunExploitScan(ctx, target, cfg, progressCh, logCh)
		default: // "full"
			findings = scan.RunFullScan(ctx, target, cfg, progressCh, logCh)
		}

		elapsed := time.Since(start)

		entry.mu.Lock()
		entry.status.Findings = findings
		entry.status.Total = len(findings)
		entry.status.Elapsed = elapsed.Round(time.Millisecond).String()
		entry.status.EndTime = time.Now().UTC().Format(time.RFC3339)
		if ctx.Err() != nil {
			entry.status.Status = "cancelled"
		} else {
			entry.status.Status = "completed"
		}
		entry.mu.Unlock()
	}()

	return id
}

// Get 返回指定扫描的当前状态。
func (m *ScanManager) Get(id string) (ScanStatus, bool) {
	m.mu.RLock()
	entry, ok := m.entries[id]
	m.mu.RUnlock()
	if !ok {
		return ScanStatus{}, false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.status, true
}

// Cancel 取消正在运行的扫描。
func (m *ScanManager) Cancel(id string) bool {
	m.mu.RLock()
	entry, ok := m.entries[id]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.status.Status != "running" {
		return false
	}
	entry.cancel()
	return true
}

// List 返回所有扫描状态。
func (m *ScanManager) List() []ScanStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]ScanStatus, 0, len(m.entries))
	for _, entry := range m.entries {
		entry.mu.Lock()
		list = append(list, entry.status)
		entry.mu.Unlock()
	}
	return list
}
