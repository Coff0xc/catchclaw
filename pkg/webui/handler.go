package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/report"
	"github.com/coff0xc/lobster-guard/pkg/utils"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍handleWS upgrades to WebSocket and registers the client.
func handleWS(state *AppState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		state.AddClient(conn)
		defer state.RemoveClient(conn)

		// Send current status on connect
		status := state.StatusJSON()
		data, _ := json.Marshal(WSMessage{Type: "status", Data: status})
		conn.WriteMessage(websocket.TextMessage, data)

		// Keep alive: read until close
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}
}

type scanRequest struct {
	Target  string `json:"target"`
	Token   string `json:"token"`
	TLS     bool   `json:"tls"`
	Timeout int    `json:"timeout"`
	Mode    string `json:"mode"`
}

// handleScan starts a scan.
func handleScan(state *AppState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Target == "" {
			jsonError(w, "target is required", http.StatusBadRequest)
			return
		}
		if req.Timeout <= 0 {
			req.Timeout = 10
		}
		if req.Mode == "" {
			req.Mode = "scan"
		}
		if err := state.StartScan(req.Target, req.Token, req.Mode, req.TLS, req.Timeout); err != nil {
			jsonError(w, err.Error(), http.StatusConflict)
			return
		}
		jsonOK(w, map[string]string{"message": "扫描已启动"})
	}
}

// handleCancel cancels the running scan.
func handleCancel(state *AppState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		state.CancelScan()
		jsonOK(w, map[string]string{"message": "已发送取消信号"})
	}
}

// handleExport exports findings as JSON file download.
func handleExport(state *AppState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		findings := make([]utils.Finding, len(state.findings))
		copy(findings, state.findings)
		target := state.target
		scanStart := state.scanStart
		state.mu.Unlock()

		if len(findings) == 0 {
			jsonError(w, "no findings to export", http.StatusNotFound)
			return
		}

		result := &utils.ScanResult{
			Target:   target,
			Findings: findings,
			StartAt:  scanStart,
			EndAt:    time.Now(),
		}

		tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("lobsterguard-%d.json", time.Now().Unix()))
		if err := report.WriteReport([]*utils.ScanResult{result}, tmpFile); err != nil {
			jsonError(w, "export failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmpFile)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=lobsterguard-report.json")
		http.ServeFile(w, r, tmpFile)
	}
}

// handleStatus returns current state.
func handleStatus(state *AppState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, state.StatusJSON())
	}
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
