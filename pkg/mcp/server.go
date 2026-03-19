package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/ai"
	"github.com/coff0xc/lobster-guard/pkg/chain"
	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/cve"
	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/fuzzer"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Server implements a Model Context Protocol (MCP) server over stdio
// using JSON-RPC 2.0, allowing AI agents to invoke LobsterGuard scanning tools
type Server struct {
	tools   map[string]ToolHandler
	version string
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolHandler processes a tool call and returns results
type ToolHandler func(params json.RawMessage) (interface{}, error)

// ToolDef describes an MCP tool for the tools/list response
type ToolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// NewServer creates a new MCP server with all LobsterGuard tools registered
func NewServer() *Server {
	s := &Server{
		tools:   make(map[string]ToolHandler),
		version: "4.0.0",
	}
	s.registerTools()
	return s
}

func (s *Server) registerTools() {
	s.tools["lobster_scan"] = s.handleScan
	s.tools["lobster_fingerprint"] = s.handleFingerprint
	s.tools["lobster_recon"] = s.handleRecon
	s.tools["lobster_exploit"] = s.handleExploit
	s.tools["lobster_audit"] = s.handleAudit
	s.tools["lobster_discover"] = s.handleDiscover
	s.tools["lobster_report"] = s.handleReport
	s.tools["lobster_ai_analyze"] = s.handleAIAnalyze
	// v4 新工具
	s.tools["lobster_cve_lookup"] = s.handleCVELookup
	s.tools["lobster_fuzz"] = s.handleFuzz
	s.tools["lobster_concurrent_scan"] = s.handleConcurrentScan
	s.tools["lobster_chain_list"] = s.handleChainList
	s.tools["lobster_vuln_stats"] = s.handleVulnStats
}

// Run starts the MCP server on stdio (blocking)
func (s *Server) Run() error {
	fmt.Fprintf(os.Stderr, "[MCP] LobsterGuard MCP Server v%s started\n", s.version)
	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read stdin: %w", err)
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := jsonRPCResponse{JSONRPC: "2.0", ID: nil, Error: &rpcError{Code: -32700, Message: "Parse error"}}
			encoder.Encode(resp)
			continue
		}

		resp := s.dispatch(req)
		encoder.Encode(resp)
	}
}

func (s *Server) dispatch(req jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":   map[string]interface{}{"tools": map[string]bool{"listChanged": false}},
				"serverInfo":     map[string]string{"name": "lobster-guard", "version": s.version},
			},
		}

	case "tools/list":
		return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{"tools": s.toolDefinitions()}}

	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "Invalid params"}}
		}
		handler, ok := s.tools[params.Name]
		if !ok {
			return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "Unknown tool: " + params.Name}}
		}
		result, err := handler(params.Arguments)
		if err != nil {
			return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
				"content": []map[string]string{{"type": "text", "text": "Error: " + err.Error()}},
				"isError": true,
			}}
		}
		text, _ := json.MarshalIndent(result, "", "  ")
		return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"content": []map[string]string{{"type": "text", "text": string(text)}},
		}}

	case "notifications/initialized":
		// Client ack, no response needed but we still send one if ID present
		if req.ID != nil {
			return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{"ok": true}}
		}
		return jsonRPCResponse{} // notification, no response

	default:
		return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "Method not found"}}
	}
}

func (s *Server) toolDefinitions() []ToolDef {
	return []ToolDef{
		{Name: "lobster_scan", Description: "Run full DAG attack chain scan against an OpenClaw instance",
			InputSchema: targetTokenSchema("Full security scan with DAG-based attack chain orchestration")},
		{Name: "lobster_fingerprint", Description: "Fingerprint an OpenClaw instance (version, auth mode, features)",
			InputSchema: targetTokenSchema("Platform fingerprinting and reconnaissance")},
		{Name: "lobster_recon", Description: "Discover OpenClaw instances on a network range",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"range":       map[string]string{"type": "string", "description": "CIDR range or host list"},
					"ports":       map[string]string{"type": "string", "description": "Ports to scan (default: 18789,18790)"},
					"concurrency": map[string]string{"type": "integer", "description": "Concurrent scan threads"},
				},
				"required": []string{"range"},
			}},
		{Name: "lobster_exploit", Description: "Run specific exploit chain by ID against a target",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target":   map[string]string{"type": "string", "description": "Target host:port"},
					"token":    map[string]string{"type": "string", "description": "Auth token"},
					"chain_id": map[string]string{"type": "integer", "description": "Chain ID (0-36)"},
				},
				"required": []string{"target", "chain_id"},
			}},
		{Name: "lobster_audit", Description: "Audit OpenClaw configuration for security issues",
			InputSchema: targetTokenSchema("Configuration security audit")},
		{Name: "lobster_discover", Description: "Discover OpenClaw instances via Shodan/Censys/FOFA",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"engine": map[string]string{"type": "string", "description": "Search engine: shodan, censys, fofa"},
					"query":  map[string]string{"type": "string", "description": "Search query"},
					"limit":  map[string]string{"type": "integer", "description": "Max results"},
				},
				"required": []string{"engine"},
			}},
		{Name: "lobster_report", Description: "Generate security assessment report from scan results",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]string{"type": "string", "description": "Target that was scanned"},
					"format": map[string]string{"type": "string", "description": "Report format: json, markdown, html"},
				},
				"required": []string{"target"},
			}},
		{Name: "lobster_ai_analyze", Description: "Use AI to analyze scan results and recommend attack paths",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"findings": map[string]string{"type": "string", "description": "JSON findings from a scan"},
					"mode":     map[string]string{"type": "string", "description": "Analysis mode: triage, attack-path, remediation"},
				},
				"required": []string{"findings"},
			}},
		// v4 新工具定义
		{Name: "lobster_cve_lookup", Description: "Search CVE database for OpenClaw/open-webui vulnerabilities",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"keyword":  map[string]string{"type": "string", "description": "Search keyword (CVE ID, description, or severity)"},
					"severity": map[string]string{"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"},
					"online":   map[string]string{"type": "boolean", "description": "Fetch latest CVEs from NVD (default: false)"},
				},
			}},
		{Name: "lobster_fuzz", Description: "AI-powered fuzzing against OpenClaw endpoints (XSS, SQLi, SSRF, CMDi, Prompt Injection)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target":     map[string]string{"type": "string", "description": "Target host:port"},
					"token":      map[string]string{"type": "string", "description": "Auth token"},
					"categories": map[string]string{"type": "string", "description": "Comma-separated: xss,sqli,ssrf,cmdi,prompt_inject"},
					"endpoints":  map[string]string{"type": "string", "description": "Comma-separated endpoint paths to fuzz"},
				},
				"required": []string{"target"},
			}},
		{Name: "lobster_concurrent_scan", Description: "High-concurrency scan with worker pool, rate limiting, and priority scheduling",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target":     map[string]string{"type": "string", "description": "Target host:port"},
					"token":      map[string]string{"type": "string", "description": "Auth token"},
					"workers":    map[string]string{"type": "integer", "description": "Max concurrent workers (default: 50)"},
					"rate_limit": map[string]string{"type": "number", "description": "Max requests per second (0 = unlimited)"},
				},
				"required": []string{"target"},
			}},
		{Name: "lobster_chain_list", Description: "List all 49+ attack chains with their categories, dependencies, and severity",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"category": map[string]string{"type": "string", "description": "Filter by category (e.g. auth, ssrf, injection, rce)"},
				},
			}},
		{Name: "lobster_vuln_stats", Description: "Get vulnerability statistics — CVE counts, severity distribution, exploit coverage",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"include_cve": map[string]string{"type": "boolean", "description": "Include CVE database stats (default: true)"},
				},
			}},
	}
}

func targetTokenSchema(desc string) map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target":     map[string]string{"type": "string", "description": "Target host:port"},
			"token":      map[string]string{"type": "string", "description": "Gateway auth token"},
			"aggressive": map[string]string{"type": "boolean", "description": "Enable aggressive mode"},
		},
		"required": []string{"target"},
	}
}

// --- Tool Handlers ---

type scanParams struct {
	Target     string `json:"target"`
	Token      string `json:"token"`
	Aggressive bool   `json:"aggressive"`
}

func (s *Server) handleScan(params json.RawMessage) (interface{}, error) {
	var p scanParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	target, err := utils.ParseTarget(p.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	concurrency := 5
	if p.Aggressive {
		concurrency = 20
	}

	cfg := chain.ChainConfig{Token: p.Token, Timeout: 15 * time.Second}
	findings := chain.RunDAGChain(target, cfg, concurrency, p.Aggressive)

	return map[string]interface{}{
		"target":       p.Target,
		"findings":     findings,
		"total":        len(findings),
		"critical":     countSev(findings, utils.SevCritical),
		"high":         countSev(findings, utils.SevHigh),
		"medium":       countSev(findings, utils.SevMedium),
		"scan_version": s.version,
	}, nil
}

func (s *Server) handleFingerprint(params json.RawMessage) (interface{}, error) {
	var p scanParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	target, err := utils.ParseTarget(p.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	findings := exploit.PlatformFingerprint(target, exploit.PlatformFingerprintConfig{Timeout: 10 * time.Second})
	return map[string]interface{}{"target": p.Target, "findings": findings}, nil
}

func (s *Server) handleRecon(params json.RawMessage) (interface{}, error) {
	return map[string]string{"status": "not_implemented", "message": "Network recon requires direct network access"}, nil
}

func (s *Server) handleExploit(params json.RawMessage) (interface{}, error) {
	var p struct {
		Target  string `json:"target"`
		Token   string `json:"token"`
		ChainID int    `json:"chain_id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	target, err := utils.ParseTarget(p.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	cfg := chain.ChainConfig{Token: p.Token, Timeout: 15 * time.Second}
	dag := chain.BuildFullDAG(5, false)
	findings := dag.ExecuteSingle(target, cfg, p.ChainID)
	return map[string]interface{}{"target": p.Target, "chain_id": p.ChainID, "findings": findings}, nil
}

func (s *Server) handleAudit(params json.RawMessage) (interface{}, error) {
	var p scanParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	target, err := utils.ParseTarget(p.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	cfg := chain.ChainConfig{Token: p.Token, Timeout: 10 * time.Second}
	// Run only config/auth category chains
	dag := chain.BuildFullDAG(3, false)
	findings := dag.ExecuteCategory(target, cfg, "config", "auth")
	return map[string]interface{}{"target": p.Target, "findings": findings, "total": len(findings)}, nil
}

func (s *Server) handleDiscover(params json.RawMessage) (interface{}, error) {
	return map[string]string{"status": "not_implemented", "message": "External search engine integration pending"}, nil
}

func (s *Server) handleReport(params json.RawMessage) (interface{}, error) {
	return map[string]string{"status": "not_implemented", "message": "Use lobster_scan results directly"}, nil
}

func (s *Server) handleAIAnalyze(params json.RawMessage) (interface{}, error) {
	return map[string]string{"status": "not_implemented", "message": "AI analysis requires API key configuration"}, nil
}

func countSev(findings []utils.Finding, sev utils.Severity) int {
	c := 0
	for _, f := range findings {
		if f.Severity == sev {
			c++
		}
	}
	return c
}

// --- v4 新 Tool Handlers ---

func (s *Server) handleCVELookup(params json.RawMessage) (interface{}, error) {
	var p struct {
		Keyword  string `json:"keyword"`
		Severity string `json:"severity"`
		Online   bool   `json:"online"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	db := cve.NewDatabase()

	// 在线获取
	if p.Online {
		online, err := db.FetchOnline("open-webui")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[CVE] Online fetch failed: %v\n", err)
		} else {
			return map[string]interface{}{
				"source":  "nvd_online",
				"results": online,
				"total":   len(online),
			}, nil
		}
	}

	// 本地搜索
	var results []cve.CVEEntry
	if p.Severity != "" {
		results = db.SearchBySeverity(p.Severity)
	} else {
		results = db.Search(p.Keyword)
	}

	return map[string]interface{}{
		"source":  "builtin",
		"results": results,
		"total":   len(results),
		"summary": db.Summary(),
	}, nil
}

func (s *Server) handleFuzz(params json.RawMessage) (interface{}, error) {
	var p struct {
		Target     string `json:"target"`
		Token      string `json:"token"`
		Categories string `json:"categories"`
		Endpoints  string `json:"endpoints"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	target, err := utils.ParseTarget(p.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	analyzer := ai.NewAnalyzer()
	f := fuzzer.NewAIFuzzer(target, p.Token, analyzer)

	var categories []string
	if p.Categories != "" {
		for _, c := range splitTrim(p.Categories, ",") {
			categories = append(categories, c)
		}
	}
	var endpoints []string
	if p.Endpoints != "" {
		for _, e := range splitTrim(p.Endpoints, ",") {
			endpoints = append(endpoints, e)
		}
	}

	results := f.Fuzz(endpoints, categories)
	findings := fuzzer.Findings(results)

	return map[string]interface{}{
		"target":       p.Target,
		"total_tests":  len(results),
		"vulns_found":  len(findings),
		"findings":     findings,
		"scan_version": s.version,
	}, nil
}

func (s *Server) handleConcurrentScan(params json.RawMessage) (interface{}, error) {
	var p struct {
		Target    string  `json:"target"`
		Token     string  `json:"token"`
		Workers   int     `json:"workers"`
		RateLimit float64 `json:"rate_limit"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	target, err := utils.ParseTarget(p.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	workers := p.Workers
	if workers <= 0 {
		workers = 50
	}

	engine := concurrent.NewEngine(workers, p.RateLimit)
	engine.Timeout = 20 * time.Second

	// 构建扫描任务: 为每个 DAG chain 创建一个 ScanTask
	dag := chain.BuildFullDAG(workers, true)
	var tasks []concurrent.ScanTask
	for i, node := range dag.Nodes {
		n := node // 捕获
		tasks = append(tasks, concurrent.ScanTask{
			ID:       n.ID,
			Name:     n.Name,
			Target:   target,
			Token:    p.Token,
			ChainID:  n.ID,
			Priority: chainPriority(n.Category),
			Execute: func(t utils.Target, token string) []utils.Finding {
				cfg := chain.ChainConfig{Token: token, Timeout: 15 * time.Second}
				return n.Execute(t, cfg)
			},
		})
		_ = i
	}

	findings := engine.Run(tasks)

	return map[string]interface{}{
		"target":       p.Target,
		"workers":      workers,
		"rate_limit":   p.RateLimit,
		"total_chains": len(tasks),
		"findings":     findings,
		"total":        len(findings),
		"critical":     countSev(findings, utils.SevCritical),
		"high":         countSev(findings, utils.SevHigh),
		"medium":       countSev(findings, utils.SevMedium),
		"scan_version": s.version,
	}, nil
}

func (s *Server) handleChainList(params json.RawMessage) (interface{}, error) {
	var p struct {
		Category string `json:"category"`
	}
	if params != nil {
		json.Unmarshal(params, &p)
	}

	dag := chain.BuildFullDAG(1, false)

	type chainInfo struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Category  string `json:"category"`
		Severity  string `json:"severity"`
		DependsOn []int  `json:"depends_on"`
	}

	var chains []chainInfo
	for _, node := range dag.Nodes {
		if p.Category != "" && node.Category != p.Category {
			continue
		}
		chains = append(chains, chainInfo{
			ID:        node.ID,
			Name:      node.Name,
			Category:  node.Category,
			Severity:  node.Severity,
			DependsOn: node.DependsOn,
		})
	}

	return map[string]interface{}{
		"total_chains": len(chains),
		"chains":       chains,
		"version":      s.version,
	}, nil
}

func (s *Server) handleVulnStats(params json.RawMessage) (interface{}, error) {
	var p struct {
		IncludeCVE *bool `json:"include_cve"`
	}
	if params != nil {
		json.Unmarshal(params, &p)
	}

	dag := chain.BuildFullDAG(1, false)

	// 攻击链统计
	categories := make(map[string]int)
	for _, node := range dag.Nodes {
		categories[node.Category]++
	}

	result := map[string]interface{}{
		"version":      s.version,
		"total_chains": len(dag.Nodes),
		"categories":   categories,
	}

	// CVE 统计 (默认包含)
	includeCVE := true
	if p.IncludeCVE != nil {
		includeCVE = *p.IncludeCVE
	}
	if includeCVE {
		db := cve.NewDatabase()
		result["cve_stats"] = db.Summary()
	}

	return result, nil
}

// --- 辅助函数 ---

func splitTrim(s, sep string) []string {
	var result []string
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func chainPriority(category string) int {
	switch category {
	case "rce", "credential":
		return 0 // 高优先级
	case "injection", "ssrf", "auth":
		return 1 // 中优先级
	default:
		return 2 // 低优先级
	}
}
