package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/scan"
	"github.com/coff0xc/lobster-guard/pkg/utils"
	"github.com/gorilla/websocket"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍WSMessage is the unified WebSocket message format.
type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// AppState holds the shared state between HTTP handlers and WebSocket broadcast.
type AppState struct {
	mu         sync.Mutex
	target     utils.Target
	token      string
	useTLS     bool
	timeout    time.Duration
	scanning   bool
	cancelScan context.CancelFunc
	findings   []utils.Finding
	logLines   []string
	scanStart  time.Time
	scanMode   string

	clients   map[*websocket.Conn]bool
	clientsMu sync.Mutex
}

// NewAppState creates a new AppState with defaults.
func NewAppState(target utils.Target, token string, useTLS bool, timeout time.Duration) *AppState {
	return &AppState{
		target:   target,
		token:    token,
		useTLS:   useTLS,
		timeout:  timeout,
		findings: []utils.Finding{},
		logLines: []string{},
		clients:  make(map[*websocket.Conn]bool),
	}
}

// AddClient registers a WebSocket connection for broadcast.
func (s *AppState) AddClient(conn *websocket.Conn) {
	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()
}

// RemoveClient unregisters a WebSocket connection.
func (s *AppState) RemoveClient(conn *websocket.Conn) {
	s.clientsMu.Lock()
	delete(s.clients, conn)
	s.clientsMu.Unlock()
}

// Broadcast sends a WSMessage to all connected WebSocket clients.
func (s *AppState) Broadcast(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	for conn := range s.clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			conn.Close()
			delete(s.clients, conn)
		}
	}
}

// StartScan launches a scan goroutine based on the given mode.
// targetStr supports: single host:port, comma/newline separated, CIDR, IP range, bare IP (default ports).
func (s *AppState) StartScan(targetStr, token, mode string, useTLS bool, timeout int) error {
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return fmt.Errorf("扫描正在进行中")
	}

	targets := scan.ParseTargets(targetStr, useTLS)
	if len(targets) == 0 {
		s.mu.Unlock()
		return fmt.Errorf("无有效目标，请检查输入格式")
	}

	s.target = targets[0]
	s.token = token
	s.useTLS = useTLS
	s.timeout = time.Duration(timeout) * time.Second
	s.scanning = true
	s.findings = []utils.Finding{}
	s.logLines = []string{}
	s.scanStart = time.Now()
	s.scanMode = mode

	ctx, cancel := context.WithCancel(context.Background())
	s.cancelScan = cancel
	s.mu.Unlock()

	go s.runScanMulti(ctx, targets, mode)
	return nil
}

// CancelScan cancels the running scan.
func (s *AppState) CancelScan() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelScan != nil {
		s.cancelScan()
	}
}

// runScanMulti scans multiple targets concurrently, broadcasting progress/findings to WS clients.
func (s *AppState) runScanMulti(ctx context.Context, targets []utils.Target, mode string) {
	progressCh := make(chan concurrent.Progress, 256)
	logCh := make(chan string, 256)

	// Consumer goroutine: forward channel messages to WS broadcast
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case p, ok := <-progressCh:
				if !ok {
					progressCh = nil
					if logCh == nil {
						return
					}
					continue
				}
				s.Broadcast(WSMessage{Type: "progress", Data: p})
			case msg, ok := <-logCh:
				if !ok {
					logCh = nil
					if progressCh == nil {
						return
					}
					continue
				}
				s.mu.Lock()
				s.logLines = append(s.logLines, msg)
				s.mu.Unlock()
				s.Broadcast(WSMessage{Type: "log", Data: map[string]string{"message": msg}})
			}
		}
	}()

	token := s.token
	timeout := s.timeout

	// 构建统一扫描配置
	cfg := scan.DefaultScanConfig()
	cfg.Token = token
	cfg.Timeout = timeout

	summary := scan.FormatTargetSummary(targets)
	scan.SendLog(logCh, fmt.Sprintf("[*] 批量扫描: %s", summary))

	var allFindings []utils.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // max 10 targets concurrently

	for i, target := range targets {
		if ctx.Err() != nil {
			scan.SendLog(logCh, "[!] 扫描已取消")
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, t utils.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			scan.SendLog(logCh, fmt.Sprintf("[*] ━━━ 目标 %d/%d: %s ━━━", idx+1, len(targets), t.String()))

			var findings []utils.Finding
			switch mode {
			case "exploit":
				findings = scan.RunExploitScan(ctx, t, cfg, progressCh, logCh)
			case "fingerprint":
				findings = scan.RunFingerprint(t, cfg, logCh)
			case "auth":
				findings = scan.RunAuthCheck(t, cfg, logCh)
			case "recon":
				findings = scan.RunReconCheck(t, cfg, logCh)
			case "audit":
				findings = scan.RunAuditCheck(t, cfg, logCh)
			default:
				findings = scan.RunFullScan(ctx, t, cfg, progressCh, logCh)
			}

			// Broadcast findings immediately per target
			for _, f := range findings {
				s.Broadcast(WSMessage{Type: "finding", Data: f})
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			if len(findings) > 0 {
				scan.SendLog(logCh, fmt.Sprintf("[+] %s: 发现 %d 个问题", t.String(), len(findings)))
			} else {
				scan.SendLog(logCh, fmt.Sprintf("[*] %s: 未发现问题", t.String()))
			}
		}(i, target)
	}
	wg.Wait()

	close(progressCh)
	close(logCh)
	<-done

	elapsed := time.Since(s.scanStart)

	s.mu.Lock()
	s.findings = allFindings
	s.scanning = false
	s.mu.Unlock()

	s.Broadcast(WSMessage{Type: "complete", Data: map[string]interface{}{
		"elapsed":        fmt.Sprintf("%.1fs", elapsed.Seconds()),
		"total_findings": len(allFindings),
		"total_targets":  len(targets),
	}})
}

// StatusJSON returns the current state as a JSON-friendly map.
func (s *AppState) StatusJSON() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]interface{}{
		"scanning": s.scanning,
		"findings": len(s.findings),
		"timeout":  int(s.timeout.Seconds()),
		"tls":      s.useTLS,
	}
	if s.target.Host != "" {
		m["target"] = s.target.String()
	}
	if s.token != "" {
		m["token"] = s.token
	}
	return m
}
