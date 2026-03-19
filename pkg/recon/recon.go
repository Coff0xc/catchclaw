package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍isSPAFallback detects nginx SPA fallback responses — all unmatched routes
// return 200 + text/html with the SPA shell. These are NOT real API endpoints.
// Also detects OAuth/Cognito redirect landing pages.
func isSPAFallback(body []byte, contentType string) bool {
	if !strings.Contains(contentType, "text/html") {
		return false
	}
	s := string(body)
	return strings.Contains(s, "openclaw-app") ||
		strings.Contains(s, "OPENCLAW_CONTROL_UI_BASE_PATH") ||
		strings.Contains(s, "OpenClaw Control") ||
		strings.Contains(s, "OpenClaw Canvas") ||
		strings.Contains(s, "<title>Sign-in</title>") ||
		strings.Contains(s, "cognito") ||
		strings.Contains(s, "oauth2/authorize") ||
		strings.Contains(s, "idpresponse")
}

// EndpointResult holds endpoint enumeration results
type EndpointResult struct {
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Auth   string `json:"auth"` // "none", "required", "unknown"
	Note   string `json:"note,omitempty"`
}

// EnumEndpoints enumerates all known OpenClaw HTTP endpoints
func EnumEndpoints(target utils.Target, token string, timeout time.Duration) ([]EndpointResult, []utils.Finding) {
	client := utils.HTTPClient(timeout)
	base := target.BaseURL()
	tStr := target.String()
	var results []EndpointResult
	var findings []utils.Finding

	fmt.Printf("\n[*] Enumerating endpoints on %s ...\n", tStr)

	type probe struct {
		method string
		path   string
		body   string
		note   string
	}

	probes := []probe{
		// Health / readiness
		{"GET", "/healthz", "", "health check"},
		{"GET", "/health", "", "health check"},
		{"GET", "/readyz", "", "readiness check"},
		{"GET", "/ready", "", "readiness check"},

		// OpenAI compat
		{"POST", "/v1/chat/completions", `{"model":"probe","messages":[]}`, "OpenAI compat chat"},
		{"POST", "/v1/responses", `{"model":"probe","input":"probe"}`, "OpenAI responses"},

		// Canvas / A2UI (both single and double underscore for compatibility)
		{"GET", "/__openclaw/canvas/", "", "Canvas host (single underscore)"},
		{"GET", "/__openclaw__/canvas/", "", "Canvas host (double underscore)"},
		{"GET", "/__openclaw/a2ui/", "", "A2UI control panel (single underscore)"},
		{"GET", "/__openclaw__/a2ui/", "", "A2UI control panel (double underscore)"},
		{"GET", "/__openclaw/control-ui-config.json", "", "Control UI config (primary fingerprint)"},

		// Hooks
		{"POST", "/hooks", `{}`, "webhook hooks (default path)"},
		{"POST", "/hooks/agent", `{}`, "webhook hooks agent"},
		{"POST", "/hooks/wake", `{}`, "webhook hooks wake"},

		// Channels
		{"POST", "/api/channels/mattermost/command", "", "Mattermost slash command"},

		// Plugin routes (common patterns)
		{"GET", "/__openclaw/plugins/", "", "plugin routes (single underscore)"},
		{"GET", "/__openclaw__/plugins/", "", "plugin routes (double underscore)"},
		{"GET", "/api/slack/events", "", "Slack events"},
		{"GET", "/api/slack/oauth", "", "Slack OAuth"},
	}

	for _, p := range probes {
		headers := map[string]string{}
		var bodyReader io.Reader
		if p.body != "" {
			bodyReader = strings.NewReader(p.body)
			headers["Content-Type"] = "application/json"
		}

		// First try without auth
		status, body, respHeaders, err := utils.DoRequest(client, p.method, base+p.path, headers, bodyReader)
		if err != nil {
			continue
		}

		// Detect SPA fallback — nginx returns 200 + HTML for all unmatched routes
		// Also catches OAuth/Cognito redirect landing pages
		ct := ""
		if respHeaders != nil {
			ct = respHeaders.Get("Content-Type")
		}
		if status == 200 && isSPAFallback(body, ct) {
			// Check if this is a known SPA path (canvas/a2ui) — those are expected
			isSPAPath := strings.Contains(p.path, "/canvas") || strings.Contains(p.path, "/a2ui") ||
				strings.Contains(p.path, "/plugins")
			if !isSPAPath {
				// Not a real endpoint — SPA/OAuth fallback, skip
				continue
			}
		}

		// For API endpoints (not static paths), reject HTML responses as non-API
		isStaticPath := strings.Contains(p.path, "/canvas") || strings.Contains(p.path, "/a2ui") ||
			strings.Contains(p.path, "/plugins") || strings.Contains(p.path, "config.json")
		if status == 200 && !isStaticPath && strings.Contains(ct, "text/html") {
			// HTML response on an API endpoint = redirect/fallback, not real access
			continue
		}

		authStatus := "unknown"
		if status == 401 || status == 403 {
			authStatus = "required"
		} else if status == 404 {
			continue // endpoint doesn't exist
		} else if status == 200 || status == 400 || status == 405 {
			authStatus = "none"
		}

		er := EndpointResult{
			Path:   p.path,
			Method: p.method,
			Status: status,
			Auth:   authStatus,
			Note:   p.note,
		}
		results = append(results, er)

		authLabel := authStatus
		if authStatus == "none" && status != 405 {
			authLabel = "NO AUTH"
		}
		fmt.Printf("  [%d] %s %s (%s) — %s\n", status, p.method, p.path, authLabel, p.note)

		// Flag unauthenticated sensitive endpoints
		if authStatus == "none" && status != 405 {
			sensitivePaths := map[string]bool{
				"/v1/chat/completions": true,
				"/v1/responses":       true,
				"/hooks":              true,
				"/hooks/agent":        true,
				"/hooks/wake":         true,
			}
			if sensitivePaths[p.path] {
				f := utils.NewFinding(tStr, "recon",
					fmt.Sprintf("Sensitive endpoint accessible without auth: %s %s", p.method, p.path),
					utils.SevHigh,
					fmt.Sprintf("%s %s returns %d without authentication", p.method, p.path, status))
				f.Evidence = fmt.Sprintf("HTTP %d (no Bearer token)", status)
				findings = append(findings, f)
			}
		}

		// If auth required and we have a token, try authenticated
		if authStatus == "required" && token != "" {
			authHeaders := map[string]string{
				"Authorization": "Bearer " + token,
			}
			var authBody io.Reader
			if p.body != "" {
				authHeaders["Content-Type"] = "application/json"
				authBody = strings.NewReader(p.body)
			}
			authStatus2, _, _, err := utils.DoRequest(client, p.method, base+p.path, authHeaders, authBody)
			if err == nil && authStatus2 != 401 && authStatus2 != 403 {
				fmt.Printf("    └─ Authenticated: %d\n", authStatus2)
			}
		}
	}

	fmt.Printf("  [*] Found %d active endpoints\n", len(results))
	return results, findings
}

// EnumWSMethods enumerates available WS RPC methods
func EnumWSMethods(target utils.Target, token string, timeout time.Duration) ([]string, []utils.Finding) {
	var available []string
	var findings []utils.Finding
	tStr := target.String()

	fmt.Printf("\n[*] Enumerating WS methods on %s ...\n", tStr)

	ws, err := utils.NewGatewayWSClient(target, token, timeout)
	if err != nil {
		fmt.Printf("  [-] WS connect failed: %v\n", err)
		return available, findings
	}
	defer ws.Close()

	// If challenge gate is active and we're not authenticated, method enumeration
	// is meaningless — all calls will fail with challenge/close errors.
	if ws.HasChallengeGate() && !ws.IsAuthenticated() {
		fmt.Printf("  [-] WS challenge gate active — method enumeration not possible without auth\n")
		f := utils.NewFinding(tStr, "recon",
			"WS challenge gate active — methods not enumerable without auth",
			utils.SevInfo,
			"WebSocket connection requires challenge-response authentication. "+
				"Method enumeration skipped to avoid false positives.")
		f.Evidence = fmt.Sprintf("Challenge nonce: %s", utils.Truncate(ws.ChallengeID(), 40))
		findings = append(findings, f)
		return available, findings
	}

	methods := []string{
		// Core info
		"config.get",
		"config.set",
		"config.openFile",
		"health",
		"system.info",
		"system-event",
		"gateway.identity.get",
		"update.check",
		"update.run",
		// Sessions
		"sessions.list",
		"sessions.preview",
		"sessions.get",
		"sessions.send",
		"sessions.delete",
		"sessions.fork",
		"sessions.patch",
		"sessions.compact",
		// Agents
		"agents.list",
		"agents.create",
		"agents.update",
		"agents.files.list",
		"agents.files.get",
		"agents.files.set",
		// Nodes & devices
		"nodes.list",
		"devices.list",
		"devices.pair",
		"node.invoke",
		"node.pending.enqueue",
		// Tools — direct invocation bypasses chat layer
		"tools.catalog",
		"tools.invoke",
		"tools.call",
		"tools.execute",
		// Files
		"files.read",
		"files.write",
		"files.list",
		"fs.read",
		"fs.write",
		"fs.list",
		// Browser
		"browser.evaluate",
		"browser.navigate",
		"browser.screenshot",
		"browser.request",
		// Secrets
		"secrets.list",
		"secrets.get",
		"secrets.export",
		// Models & chat
		"models.list",
		"chat.history",
		"talk.config",
		// Cron
		"cron.list",
		"cron.create",
		// Logs
		"logs.query",
		"logs.list",
		// Exec approvals
		"exec.approvals.get",
		"exec.approvals.set",
		"exec.approval.resolve",
		// Evaluate / exec
		"evaluate",
		// Skills
		"skills.install",
		"skills.update",
		// Web login
		"web.login.start",
		"web.login.wait",
		// Wizard
		"wizard.start",
		"wizard.status",
		// Push / misc
		"push.test",
		"doctor.memory.status",
		"wake",
	}

	for _, method := range methods {
		result, err := ws.Call(method, nil)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "unknown method") ||
				strings.Contains(errStr, "not found") ||
				strings.Contains(errStr, "not implemented") {
				continue
			}
			// Method exists but returned error (e.g. missing params)
			available = append(available, method+" (error: "+truncate(errStr, 60)+")")
			fmt.Printf("  [*] %s → error (exists): %s\n", method, truncate(errStr, 80))
			continue
		}

		available = append(available, method)
		dataLen := len(result)
		fmt.Printf("  [+] %s → OK (%d bytes)\n", method, dataLen)

		// Check for sensitive data exposure
		if method == "secrets.list" && dataLen > 2 {
			f := utils.NewFinding(tStr, "recon",
				"secrets.list returns data via WS",
				utils.SevHigh,
				"Secret references accessible via WebSocket RPC")
			f.Evidence = fmt.Sprintf("secrets.list returned %d bytes", dataLen)
			findings = append(findings, f)
		}
		if method == "chat.history" && dataLen > 2 {
			f := utils.NewFinding(tStr, "recon",
				"chat.history accessible — conversation data exposed",
				utils.SevMedium,
				"Chat history readable via WS — may contain sensitive user data")
			f.Evidence = fmt.Sprintf("chat.history returned %d bytes", dataLen)
			findings = append(findings, f)
		}
		// Deep analysis of tools.catalog — identify dangerous tools
		if method == "tools.catalog" && dataLen > 2 {
			resultStr := string(result)
			dangerousTools := []struct {
				name string
				sev  utils.Severity
				desc string
			}{
				{"system.run", utils.SevCritical, "Arbitrary command execution"},
				{"bash", utils.SevCritical, "Shell command execution"},
				{"shell", utils.SevCritical, "Shell command execution"},
				{"exec", utils.SevCritical, "Process execution"},
				{"fs.write", utils.SevHigh, "Arbitrary file write"},
				{"fs.read", utils.SevHigh, "Arbitrary file read"},
				{"apply_patch", utils.SevHigh, "File write (path traversal risk)"},
				{"browser.evaluate", utils.SevHigh, "JavaScript eval in browser context"},
				{"browser.navigate", utils.SevMedium, "Browser navigation (SSRF vector)"},
				{"computer_use", utils.SevCritical, "Full computer control"},
				{"mcp_", utils.SevMedium, "MCP tool (external integration)"},
			}
			found := []string{}
			for _, dt := range dangerousTools {
				if strings.Contains(resultStr, dt.name) {
					found = append(found, dt.name)
				}
			}
			if len(found) > 0 {
				f := utils.NewFinding(tStr, "recon",
					fmt.Sprintf("tools.catalog exposes %d dangerous tools", len(found)),
					utils.SevHigh,
					fmt.Sprintf("Dangerous tools available: %s — direct invocation via tools.invoke bypasses chat-layer security", strings.Join(found, ", ")))
				f.Evidence = fmt.Sprintf("tools.catalog (%d bytes), dangerous: %s", dataLen, strings.Join(found, ", "))
				f.Remediation = "Add dangerous tools to tools.deny; restrict tools.catalog access"
				findings = append(findings, f)
				fmt.Printf("  [!!!] %d dangerous tools in catalog: %s\n", len(found), strings.Join(found, ", "))
			}
		}
		// Flag config.set write access
		if method == "config.set" {
			f := utils.NewFinding(tStr, "recon",
				"config.set method accessible",
				utils.SevCritical,
				"config.set is available — attacker can modify gateway configuration at runtime (disable auth, enable SSRF, etc.)")
			f.Evidence = fmt.Sprintf("config.set returned %d bytes", dataLen)
			findings = append(findings, f)
			fmt.Printf("  [!!!] config.set writable!\n")
		}
		// Flag direct tool invocation methods
		if (method == "tools.invoke" || method == "tools.call" || method == "tools.execute") && dataLen >= 0 {
			f := utils.NewFinding(tStr, "recon",
				fmt.Sprintf("%s method accessible — direct tool invocation", method),
				utils.SevCritical,
				fmt.Sprintf("%s bypasses chat-layer security (Shield.md, prompt injection detection, tool deny lists)", method))
			f.Evidence = fmt.Sprintf("%s responded (%d bytes)", method, dataLen)
			findings = append(findings, f)
			fmt.Printf("  [!!!] %s accessible — bypasses chat security!\n", method)
		}
	}

	fmt.Printf("  [*] %d/%d WS methods available\n", len(available), len(methods))

	if len(available) > 0 {
		f := utils.NewFinding(tStr, "recon",
			fmt.Sprintf("WS method enumeration: %d methods accessible", len(available)),
			utils.SevInfo,
			fmt.Sprintf("Available methods: %s", strings.Join(available, ", ")))
		findings = append(findings, f)
	}

	return available, findings
}

// VersionDetect attempts to extract OpenClaw version info
func VersionDetect(target utils.Target, timeout time.Duration) (string, []utils.Finding) {
	client := utils.HTTPClient(timeout)
	base := target.BaseURL()
	tStr := target.String()
	var findings []utils.Finding

	fmt.Printf("\n[*] Detecting version on %s ...\n", tStr)

	// Try /healthz
	status, body, headers, err := utils.DoRequest(client, "GET", base+"/healthz", nil, nil)
	if err == nil && status == 200 {
		var health map[string]interface{}
		if json.Unmarshal(body, &health) == nil {
			if v, ok := health["version"]; ok {
				version := fmt.Sprintf("%v", v)
				fmt.Printf("  [+] Version from /healthz: %s\n", version)

				f := utils.NewFinding(tStr, "recon",
					fmt.Sprintf("OpenClaw version detected: %s", version),
					utils.SevInfo,
					"Version information exposed via health endpoint")
				f.Evidence = fmt.Sprintf("GET /healthz → version: %s", version)
				findings = append(findings, f)
				return version, findings
			}
		}

		// Check server header
		if sv := headers.Get("Server"); sv != "" {
			fmt.Printf("  [*] Server header: %s\n", sv)
		}
	}

	fmt.Printf("  [-] Version not detected\n")
	return "", findings
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
