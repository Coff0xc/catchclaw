package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Coff0xc/catchclaw/go/internal/config"
	"github.com/Coff0xc/catchclaw/go/internal/core"
	"github.com/Coff0xc/catchclaw/go/internal/exploit"
	"github.com/Coff0xc/catchclaw/go/internal/nuclei"
	"github.com/Coff0xc/catchclaw/go/internal/osint"
	"github.com/Coff0xc/catchclaw/go/internal/scan"
)

const (
	protocolVersion = "2024-11-05"
	serverName      = "catchclaw"
	serverVersion   = "6.0.0"
	maxRequestBytes = 1 << 20
	maxFindingsOut  = 100
	maxEvidenceLen  = 300
	maxTimeoutSec   = 300
	scanCooldown    = 2 * time.Second
)

type Options struct {
	AllowedTargets []string
	NucleiDir      string
	AuditLog       io.Writer
}

type Server struct {
	opts       Options
	allowNets  []netip.Prefix
	allowHosts map[string]bool
	scanMu     sync.Mutex
	lastScan   time.Time
	out        *json.Encoder
	encMu      sync.Mutex
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

func New(opts Options) *Server {
	if opts.AuditLog == nil {
		opts.AuditLog = os.Stderr
	}
	s := &Server{
		opts:       opts,
		allowHosts: make(map[string]bool),
	}
	defaultAllow := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"::1/128", "fc00::/7", "localhost",
	}
	for _, t := range append(defaultAllow, opts.AllowedTargets...) {
		s.addAllowed(t)
	}
	return s
}

func (s *Server) addAllowed(entry string) {
	entry = strings.TrimSpace(strings.ToLower(entry))
	if entry == "" {
		return
	}
	if _, p, err := net.ParseCIDR(entry); err == nil {
		if prefix, err := netip.ParsePrefix(p.String()); err == nil {
			s.allowNets = append(s.allowNets, prefix)
		}
		return
	}
	if addr, err := netip.ParseAddr(entry); err == nil {
		s.allowNets = append(s.allowNets, netip.PrefixFrom(addr, addr.BitLen()))
		return
	}
	s.allowHosts[entry] = true
}

func (s *Server) audit(format string, args ...interface{}) {
	fmt.Fprintf(s.opts.AuditLog, "[mcp-audit %s] %s\n",
		time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

func (s *Server) validateTarget(raw string) (*core.Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 256 {
		return nil, fmt.Errorf("invalid target length")
	}
	for _, c := range raw {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == ':', c == '[', c == ']':
		default:
			return nil, fmt.Errorf("target contains invalid character %q", c)
		}
	}

	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, fmt.Errorf("target must be host:port — %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range")
	}

	lowerHost := strings.ToLower(host)
	if s.allowHosts[lowerHost] {
		t := core.Target{Host: host, Port: port}
		return &t, nil
	}

	ips := []netip.Addr{}
	if addr, err := netip.ParseAddr(host); err == nil {
		ips = append(ips, addr)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resolved, err := net.DefaultResolver.LookupHost(ctx, host)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("cannot resolve host: %v", err)
		}
		for _, r := range resolved {
			if addr, err := netip.ParseAddr(r); err == nil {
				ips = append(ips, addr)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses resolved")
	}

	for _, ip := range ips {
		allowed := false
		for _, p := range s.allowNets {
			if p.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("target %s (%s) not in allowlist — pass --allow to permit", host, ip)
		}
	}

	t := core.Target{Host: host, Port: port}
	return &t, nil
}

func (s *Server) clampTimeout(v float64) int {
	if v <= 0 {
		return 10
	}
	if v > maxTimeoutSec {
		return maxTimeoutSec
	}
	return int(v)
}

func (s *Server) acquireScan() error {
	s.scanMu.Lock()
	wait := scanCooldown - time.Since(s.lastScan)
	if wait > 0 {
		time.Sleep(wait)
	}
	return nil
}

func (s *Server) releaseScan() {
	s.lastScan = time.Now()
	s.scanMu.Unlock()
}

func schema(props map[string]interface{}, required []string) map[string]interface{} {
	s := map[string]interface{}{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strProp(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "description": desc}
}

func numProp(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "number", "description": desc}
}

func (s *Server) tools() []toolDef {
	return []toolDef{
		{"catchclaw_scan", "Run full CatchClaw security scan (412 modules, DAG orchestrated) against an allowlisted target. Returns findings summary.",
			schema(map[string]interface{}{
				"target":  strProp("host:port, must be in allowlist"),
				"timeout": numProp("per-request timeout seconds, max 300"),
				"token":   strProp("optional auth token for the target"),
			}, []string{"target"})},
		{"catchclaw_chain", "Run multi-stage attack chains (state-passing: stolen tokens/creds flow between stages). Returns per-chain stage results.",
			schema(map[string]interface{}{
				"target":   strProp("host:port, must be in allowlist"),
				"chain_id": strProp("optional: run only this chain ID, e.g. chain_ray_shadow"),
				"timeout":  numProp("timeout seconds, max 300"),
			}, []string{"target"})},
		{"catchclaw_discover", "Port scan + AI platform fingerprinting on an allowlisted host.",
			schema(map[string]interface{}{
				"host":    strProp("hostname or IP, must be in allowlist"),
				"timeout": numProp("timeout seconds, max 60"),
			}, []string{"host"})},
		{"catchclaw_nuclei", "Run bundled Nuclei templates against an allowlisted target URL.",
			schema(map[string]interface{}{
				"target": strProp("http(s)://host:port, host must be in allowlist"),
			}, []string{"target"})},
		{"catchclaw_list_modules", "List registered exploit modules.",
			schema(map[string]interface{}{
				"prefix": strProp("optional ID prefix filter, e.g. chain_ or ollama"),
			}, nil)},
		{"catchclaw_list_chains", "List multi-stage attack chain definitions with their stages.", schema(map[string]interface{}{}, nil)},
		{"catchclaw_osint", "Search Shodan / FOFA / Hunter cyberspace engines for exposed AI platforms. API keys come from server env (SHODAN_API_KEY, FOFA_EMAIL+FOFA_KEY, HUNTER_API_KEY) — never pass keys as arguments.",
			schema(map[string]interface{}{
				"engine":   strProp("shodan | fofa | hunter"),
				"query":    strProp("raw engine dork, max 256 chars"),
				"platform": strProp("alternative: built-in dork name, e.g. ollama, ray, dify"),
				"size":     numProp("max results, cap 100"),
			}, []string{"engine"})},
	}
}

func textResult(text string, isErr bool) map[string]interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": text}},
		"isError": isErr,
	}
}

func findingsJSON(findings []core.Finding) string {
	if len(findings) > maxFindingsOut {
		findings = findings[:maxFindingsOut]
	}
	type slim struct {
		Module   string `json:"module"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Evidence string `json:"evidence,omitempty"`
	}
	out := make([]slim, 0, len(findings))
	for _, f := range findings {
		out = append(out, slim{f.Module, f.Title, f.Severity.String(), core.TruncateStr(f.Evidence, maxEvidenceLen)})
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	return string(data)
}

func (s *Server) callTool(name string, argsRaw json.RawMessage) map[string]interface{} {
	var args map[string]interface{}
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return textResult("invalid arguments: "+err.Error(), true)
		}
	}
	start := time.Now()
	s.audit("tool=%s args=%s", name, core.TruncateStr(string(argsRaw), 200))
	defer func() {
		s.audit("tool=%s done duration=%v", name, time.Since(start))
	}()

	strArg := func(k string) string {
		if v, ok := args[k].(string); ok {
			return v
		}
		return ""
	}
	numArg := func(k string) float64 {
		if v, ok := args[k].(float64); ok {
			return v
		}
		return 0
	}

	switch name {
	case "catchclaw_scan":
		t, err := s.validateTarget(strArg("target"))
		if err != nil {
			return textResult("target rejected: "+err.Error(), true)
		}
		if err := s.acquireScan(); err != nil {
			return textResult("scan busy, retry later", true)
		}
		defer s.releaseScan()

		cfg := config.Default()
		cfg.Timeout = time.Duration(s.clampTimeout(numArg("timeout"))) * time.Second
		cfg.Quiet = true
		if tok := strArg("token"); tok != "" {
			cfg.Token = tok
			t.Token = tok
		}
		result := scan.NewScanner(cfg).Scan(*t)
		return textResult(fmt.Sprintf("Scan of %s complete: %d findings (risk %d/100)\n\n%s",
			t, len(result.Findings), result.ChainScore(), findingsJSON(result.Findings)), false)

	case "catchclaw_chain":
		t, err := s.validateTarget(strArg("target"))
		if err != nil {
			return textResult("target rejected: "+err.Error(), true)
		}
		if err := s.acquireScan(); err != nil {
			return textResult("scan busy, retry later", true)
		}
		defer s.releaseScan()

		cfg := config.Default()
		cfg.Timeout = time.Duration(s.clampTimeout(numArg("timeout"))) * time.Second
		cfg.Quiet = true
		chainID := strArg("chain_id")

		exploit.ResetTracesFor(t.String())
		var findings []core.Finding
		for _, m := range exploit.GlobalRegistry().All() {
			id := m.Meta().ID
			if !strings.HasPrefix(id, "chain_") {
				continue
			}
			if chainID != "" && id != chainID {
				continue
			}
			f, _ := m.Run(*t, cfg)
			findings = append(findings, f...)
		}

		var sb strings.Builder
		fmt.Fprintf(&sb, "Chains against %s: %d findings\n\n", t, len(findings))
		for _, tr := range exploit.TracesFor(t.String()) {
			status := "PARTIAL"
			if tr.Complete {
				status = "FULL COMPROMISE"
			}
			fmt.Fprintf(&sb, "[%s] %s\n", status, tr.ChainName)
			for i, st := range tr.Stages {
				mark := "✗"
				if st.Hit {
					mark = "✓"
				}
				fmt.Fprintf(&sb, "  %s stage %d: %s\n", mark, i+1, st.Name)
			}
		}
		return textResult(sb.String(), false)

	case "catchclaw_discover":
		host := strArg("host")
		if host == "" {
			return textResult("host required", true)
		}
		if _, err := s.validateTarget(net.JoinHostPort(host, "80")); err != nil {
			return textResult("host rejected: "+err.Error(), true)
		}
		results := scan.DiscoverServices(host, nil, 5*time.Second, 50)
		var sb strings.Builder
		fmt.Fprintf(&sb, "Discovery on %s: %d open services\n", host, len(results))
		for _, r := range results {
			fmt.Fprintf(&sb, "  %s:%d [%s]\n", r.Host, r.Port, r.Platform)
		}
		return textResult(sb.String(), false)

	case "catchclaw_nuclei":
		raw := strArg("target")
		scheme := "http"
		if strings.HasPrefix(raw, "https://") {
			scheme = "https"
		}
		raw = strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
		t, err := s.validateTarget(raw)
		if err != nil {
			return textResult("target rejected: "+err.Error(), true)
		}
		dir := s.opts.NucleiDir
		if dir == "" {
			dir = "../nuclei-templates"
		}
		runner := nuclei.NewRunner(dir)
		if err := runner.LoadTemplates(); err != nil {
			return textResult("template load failed: "+err.Error(), true)
		}
		if t.Port == 443 {
			scheme = "https"
		}
		findings := runner.RunAll(fmt.Sprintf("%s://%s", scheme, t.String()))
		var sb strings.Builder
		fmt.Fprintf(&sb, "Nuclei: %d findings from %d templates\n", len(findings), len(runner.Templates))
		for _, f := range findings {
			fmt.Fprintf(&sb, "  [%s] %s (%s)\n    %s\n", f.Severity, f.Name, f.TemplateID, f.URL)
		}
		return textResult(sb.String(), false)

	case "catchclaw_osint":
		engine := strArg("engine")
		q := strArg("query")
		if q == "" {
			if p := strArg("platform"); p != "" {
				dork, ok := osint.DorkFor(p, engine)
				if !ok {
					return textResult(fmt.Sprintf("no built-in dork for platform %q on %s", p, engine), true)
				}
				q = dork
			}
		}
		hosts, err := osint.Query(engine, q, int(numArg("size")))
		if err != nil {
			return textResult("osint query failed: "+err.Error(), true)
		}
		if len(hosts) > maxFindingsOut {
			hosts = hosts[:maxFindingsOut]
		}
		type slimHost struct {
			IP    string `json:"ip"`
			Port  int    `json:"port"`
			Host  string `json:"host,omitempty"`
			Org   string `json:"org,omitempty"`
			Title string `json:"title,omitempty"`
		}
		out := make([]slimHost, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, slimHost{h.IP, h.Port,
				core.TruncateStr(h.Host, 100), core.TruncateStr(h.Org, 100), core.TruncateStr(h.Title, maxEvidenceLen)})
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		return textResult(fmt.Sprintf("%d hosts from %s (query: %s)\n\n%s", len(hosts), engine, q, data), false)

	case "catchclaw_list_modules":
		prefix := strArg("prefix")
		var sb strings.Builder
		count := 0
		for _, m := range exploit.GlobalRegistry().Sorted() {
			meta := m.Meta()
			if prefix != "" && !strings.HasPrefix(meta.ID, prefix) {
				continue
			}
			cve := ""
			if meta.CVE != "" {
				cve = " [" + meta.CVE + "]"
			}
			fmt.Fprintf(&sb, "%s — %s (%s/%s)%s\n", meta.ID, meta.Name, meta.Category, meta.Phase, cve)
			count++
		}
		return textResult(fmt.Sprintf("%d modules\n\n%s", count, sb.String()), false)

	case "catchclaw_list_chains":
		var sb strings.Builder
		count := 0
		for _, m := range exploit.GlobalRegistry().All() {
			meta := m.Meta()
			if strings.HasPrefix(meta.ID, "chain_") {
				fmt.Fprintf(&sb, "%s — %s\n", meta.ID, meta.Name)
				count++
			}
		}
		return textResult(fmt.Sprintf("%d attack chains\n\n%s", count, sb.String()), false)
	}

	return textResult("unknown tool: "+name, true)
}

func (s *Server) respond(id json.RawMessage, result interface{}, rpcErr *rpcError) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr}
	s.encMu.Lock()
	defer s.encMu.Unlock()
	s.out.Encode(resp)
}

func readLine(r *bufio.Reader) ([]byte, bool, error) {
	var buf []byte
	tooLong := false
	for {
		frag, err := r.ReadSlice('\n')
		if !tooLong {
			buf = append(buf, frag...)
			if len(buf) > maxRequestBytes {
				tooLong = true
				buf = nil
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return buf, tooLong, err
	}
}

func (s *Server) Serve(in io.Reader, out io.Writer) error {
	s.out = json.NewEncoder(out)
	reader := bufio.NewReaderSize(in, 64*1024)

	for {
		line, tooLong, err := readLine(reader)
		if tooLong {
			s.audit("oversized request dropped (>%d bytes)", maxRequestBytes)
			s.respond(nil, nil, &rpcError{Code: -32600, Message: "request too large"})
		} else if len(strings.TrimSpace(string(line))) > 0 {
			var req rpcRequest
			if jerr := json.Unmarshal(line, &req); jerr != nil {
				s.respond(nil, nil, &rpcError{Code: -32700, Message: "parse error"})
			} else {
				s.dispatch(&req)
			}
		}
		if err != nil {
			return err
		}
	}
}

func (s *Server) dispatch(req *rpcRequest) {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &params)
		s.audit("initialize client_protocol=%s", params.ProtocolVersion)
		s.respond(req.ID, map[string]interface{}{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    serverName,
				"version": serverVersion,
			},
		}, nil)

	case "notifications/initialized", "initialized":
		s.audit("client initialized")

	case "ping":
		s.respond(req.ID, map[string]interface{}{}, nil)

	case "tools/list":
		s.respond(req.ID, map[string]interface{}{"tools": s.tools()}, nil)

	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.respond(req.ID, nil, &rpcError{Code: -32602, Message: "invalid params"})
			return
		}
		s.respond(req.ID, s.callTool(params.Name, params.Arguments), nil)

	default:
		if req.ID != nil {
			s.respond(req.ID, nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
		}
	}
}
