package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/cve"
	"github.com/coff0xc/lobster-guard/pkg/scan"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍--- Health ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": "4.1.0",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// --- Scan ---

// ScanRequest 定义扫描请求参数。
type ScanRequest struct {
	Target          string  `json:"target"`
	Token           string  `json:"token"`
	TLS             bool    `json:"tls"`
	Timeout         int     `json:"timeout"`
	Mode            string  `json:"mode"`
	Aggressive      bool    `json:"aggressive"`
	UltraAggressive bool    `json:"ultra_aggressive"`
	NoBrute         bool    `json:"no_brute"`
	NoExploit       bool    `json:"no_exploit"`
	ChainID         int     `json:"chain_id"`
	Workers         int     `json:"workers"`
	RateLimit       float64 `json:"rate_limit"`
	HookToken       string  `json:"hook_token"`
	HookPath        string  `json:"hook_path"`
	CallbackURL     string  `json:"callback_url"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Target == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	t, err := utils.ParseTarget(req.Target)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid target: %v", err)})
		return
	}
	t.UseTLS = req.TLS

	cfg := scan.DefaultScanConfig()
	cfg.Token = req.Token
	cfg.Aggressive = req.Aggressive
	cfg.UltraAggressive = req.UltraAggressive
	cfg.NoBrute = req.NoBrute
	cfg.NoExploit = req.NoExploit
	cfg.Workers = req.Workers
	cfg.RateLimit = req.RateLimit
	cfg.HookToken = req.HookToken
	cfg.HookPath = req.HookPath
	cfg.CallbackURL = req.CallbackURL
	if req.ChainID != 0 {
		cfg.ChainID = req.ChainID
	}
	if req.Timeout > 0 {
		cfg.Timeout = time.Duration(req.Timeout) * time.Second
	}

	mode := req.Mode
	if mode == "" {
		mode = "full"
	}

	id := s.scans.Start(t, cfg, mode)

	jsonResp(w, http.StatusAccepted, map[string]any{
		"id":      id,
		"status":  "running",
		"target":  t.String(),
		"mode":    mode,
		"message": "扫描已启动",
	})
}

// handleScanByID 处理 GET /api/v1/scan/{id} 和 POST /api/v1/scan/{id}/cancel
func (s *Server) handleScanByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scan/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	if id == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "scan id required"})
		return
	}

	// POST /api/v1/scan/{id}/cancel
	if len(parts) == 2 && parts[1] == "cancel" {
		if r.Method != http.MethodPost {
			jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST to cancel"})
			return
		}
		if s.scans.Cancel(id) {
			jsonResp(w, http.StatusOK, map[string]string{"status": "cancelled", "id": id})
		} else {
			jsonResp(w, http.StatusNotFound, map[string]string{"error": "scan not found or already completed"})
		}
		return
	}

	// GET /api/v1/scan/{id}
	if r.Method != http.MethodGet {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
		return
	}
	result, ok := s.scans.Get(id)
	if !ok {
		jsonResp(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}
	jsonResp(w, http.StatusOK, result)
}

// handleListScans 返回所有扫描状态。
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
		return
	}
	jsonResp(w, http.StatusOK, s.scans.List())
}

// --- CVE ---

func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
		return
	}
	db := cve.NewDatabase()
	keyword := r.URL.Query().Get("q")

	var results []cve.CVEEntry
	if keyword != "" {
		results = db.Search(keyword)
	} else {
		results = db.All()
	}

	jsonResp(w, http.StatusOK, map[string]any{
		"total":   len(results),
		"results": results,
	})
}
