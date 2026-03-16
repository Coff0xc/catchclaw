package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/chain"
	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// Server implements a Model Context Protocol (MCP) server over stdio
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
		version: "2.0.0",
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
