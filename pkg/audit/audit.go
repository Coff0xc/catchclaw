package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍AuditConfig holds audit module configuration
type AuditConfig struct {
	Token   string
	Timeout time.Duration
}

// RunAudit performs configuration security audit via WS and HTTP
func RunAudit(target utils.Target, cfg AuditConfig) []utils.Finding {
	var findings []utils.Finding
	tStr := target.String()

	fmt.Printf("\n[*] Running configuration audit on %s ...\n", tStr)

	// Try WS connection for config extraction
	wsFindings := auditViaWS(target, cfg)
	findings = append(findings, wsFindings...)

	// HTTP-based config checks
	httpFindings := auditViaHTTP(target, cfg)
	findings = append(findings, httpFindings...)

	if len(findings) == 0 {
		fmt.Printf("  [+] No dangerous configuration flags detected\n")
	}

	return findings
}

func auditViaWS(target utils.Target, cfg AuditConfig) []utils.Finding {
	var findings []utils.Finding
	tStr := target.String()

	ws, err := utils.NewGatewayWSClient(target, cfg.Token, cfg.Timeout)
	if err != nil {
		fmt.Printf("  [-] WS connect failed: %v\n", err)
		return findings
	}
	defer ws.Close()
	fmt.Printf("  [+] WS connected to %s\n", target.WsURL())

	// 1. Try config.get
	configFindings := auditConfigGet(ws, tStr)
	findings = append(findings, configFindings...)

	// 2. Try sessions.list — check for exposed sessions
	sessFindings := auditSessionsList(ws, tStr)
	findings = append(findings, sessFindings...)

	// 3. Try agents.list — enumerate agents
	agentFindings := auditAgentsList(ws, tStr)
	findings = append(findings, agentFindings...)

	// 4. Try nodes.list — check for paired nodes
	nodeFindings := auditNodesList(ws, tStr)
	findings = append(findings, nodeFindings...)

	// 5. Try secrets.list — check for exposed secrets
	secretFindings := auditSecretsList(ws, tStr)
	findings = append(findings, secretFindings...)

	return findings
}

func auditConfigGet(ws *utils.GatewayWSClient, tStr string) []utils.Finding {
	var findings []utils.Finding

	result, err := ws.Call("config.get", nil)
	if err != nil {
		fmt.Printf("  [-] config.get failed: %v\n", err)
		return findings
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal(result, &config); err != nil {
		fmt.Printf("  [-] config.get parse failed: %v\n", err)
		return findings
	}

	fmt.Printf("  [+] config.get succeeded — analyzing configuration\n")

	configStr := string(result)

	// Check dangerous flags
	dangerousChecks := []struct {
		path     string
		pattern  string
		severity utils.Severity
		title    string
		desc     string
		remedy   string
	}{
		{
			"gateway.controlUi.dangerouslyDisableDeviceAuth",
			`"dangerouslyDisableDeviceAuth":true`,
			utils.SevHigh,
			"Device auth disabled (dangerouslyDisableDeviceAuth=true)",
			"Control UI device authentication is disabled — any browser can access the UI",
			"Set gateway.controlUi.dangerouslyDisableDeviceAuth to false",
		},
		{
			"gateway.controlUi.allowInsecureAuth",
			`"allowInsecureAuth":true`,
			utils.SevHigh,
			"Insecure auth allowed (allowInsecureAuth=true)",
			"Control UI allows insecure (non-TLS) authentication",
			"Set gateway.controlUi.allowInsecureAuth to false",
		},
		{
			"gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback",
			`"dangerouslyAllowHostHeaderOriginFallback":true`,
			utils.SevHigh,
			"Host header origin fallback enabled",
			"Origin check falls back to Host header — CSRF bypass possible",
			"Set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback to false",
		},
		{
			"hooks.gmail.allowUnsafeExternalContent",
			`"allowUnsafeExternalContent":true`,
			utils.SevHigh,
			"Unsafe external content allowed in hooks",
			"External content (email/webhook) bypasses security wrapping — prompt injection risk",
			"Set allowUnsafeExternalContent to false",
		},
		{
			"tools.exec.applyPatch.workspaceOnly",
			`"workspaceOnly":false`,
			utils.SevHigh,
			"apply_patch not restricted to workspace",
			"apply_patch can write/delete files outside workspace directory",
			"Set tools.exec.applyPatch.workspaceOnly to true",
		},
		{
			"agents.defaults.sandbox.mode off",
			`"sandbox"`,
			utils.SevInfo, // will be upgraded if mode=off detected
			"Sandbox configuration detected",
			"Checking sandbox mode...",
			"",
		},
		{
			"gateway.auth.mode none",
			`"mode":"none"`,
			utils.SevCritical,
			"Gateway auth mode is 'none'",
			"Gateway has no authentication — anyone can access all endpoints",
			"Set gateway.auth.mode to 'token' or 'password' with a strong credential",
		},
		{
			"gateway.bind lan",
			`"bind":"lan"`,
			utils.SevHigh,
			"Gateway bound to LAN (0.0.0.0)",
			"Gateway listens on all interfaces — exposed to network",
			"Set gateway.bind to 'loopback' unless remote access is required",
		},
		{
			"browser.ssrfPolicy.dangerouslyAllowPrivateNetwork",
			`"dangerouslyAllowPrivateNetwork":true`,
			utils.SevHigh,
			"Browser SSRF protection disabled",
			"Browser tool can access private/internal network addresses",
			"Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false",
		},
	}

	for _, check := range dangerousChecks {
		if strings.Contains(configStr, check.pattern) {
			f := utils.NewFinding(tStr, "audit", check.title, check.severity, check.desc)
			f.Evidence = fmt.Sprintf("Config path: %s", check.path)
			f.Remediation = check.remedy
			findings = append(findings, f)
			sev := check.severity.Color()
			fmt.Printf("  ")
			sev.Printf("[%s]", check.severity)
			fmt.Printf(" %s\n", check.title)
		}
	}

	// Check sandbox mode specifically
	if strings.Contains(configStr, `"mode":"off"`) || !strings.Contains(configStr, `"sandbox"`) {
		f := utils.NewFinding(tStr, "audit",
			"Sandbox is disabled (mode=off)",
			utils.SevHigh,
			"Agent exec runs directly on host — no container isolation")
		f.Evidence = "sandbox.mode = off (or not configured)"
		f.Remediation = "Set agents.defaults.sandbox.mode to 'non-main' or 'all'"
		findings = append(findings, f)
		fmt.Printf("  [HIGH] Sandbox is disabled — exec runs on host\n")
	}

	// Check for wildcard origin
	if strings.Contains(configStr, `"*"`) && strings.Contains(configStr, `"allowedOrigins"`) {
		f := utils.NewFinding(tStr, "audit",
			"Wildcard origin allowed (*)",
			utils.SevHigh,
			"CORS/Origin check allows any origin — CSRF attacks possible")
		f.Remediation = "Remove '*' from gateway.controlUi.allowedOrigins"
		findings = append(findings, f)
		fmt.Printf("  [HIGH] Wildcard origin (*) in allowedOrigins\n")
	}

	return findings
}

func auditSessionsList(ws *utils.GatewayWSClient, tStr string) []utils.Finding {
	var findings []utils.Finding

	result, err := ws.Call("sessions.list", nil)
	if err != nil {
		return findings
	}

	var sessions []json.RawMessage
	if json.Unmarshal(result, &sessions) == nil && len(sessions) > 0 {
		f := utils.NewFinding(tStr, "audit",
			fmt.Sprintf("Sessions exposed: %d active sessions", len(sessions)),
			utils.SevMedium,
			"sessions.list returns active session data — session hijacking possible if shared gateway")
		f.Evidence = fmt.Sprintf("%d sessions returned", len(sessions))
		findings = append(findings, f)
		fmt.Printf("  [MEDIUM] %d active sessions exposed via sessions.list\n", len(sessions))
	}

	return findings
}

func auditAgentsList(ws *utils.GatewayWSClient, tStr string) []utils.Finding {
	var findings []utils.Finding

	result, err := ws.Call("agents.list", nil)
	if err != nil {
		return findings
	}

	var agents []json.RawMessage
	if json.Unmarshal(result, &agents) == nil && len(agents) > 0 {
		fmt.Printf("  [*] %d agent(s) configured\n", len(agents))
		// Info-level: useful for recon
		f := utils.NewFinding(tStr, "audit",
			fmt.Sprintf("Agent enumeration: %d agents configured", len(agents)),
			utils.SevInfo,
			"agents.list reveals configured agent details")
		f.Evidence = fmt.Sprintf("%d agents: %s", len(agents), truncateJSON(result, 300))
		findings = append(findings, f)
	}

	return findings
}

func auditNodesList(ws *utils.GatewayWSClient, tStr string) []utils.Finding {
	var findings []utils.Finding

	result, err := ws.Call("nodes.list", nil)
	if err != nil {
		return findings
	}

	var nodes []json.RawMessage
	if json.Unmarshal(result, &nodes) == nil && len(nodes) > 0 {
		f := utils.NewFinding(tStr, "audit",
			fmt.Sprintf("Paired nodes found: %d remote execution nodes", len(nodes)),
			utils.SevMedium,
			"nodes.list reveals paired execution nodes — each node has operator-level remote exec")
		f.Evidence = fmt.Sprintf("%d nodes: %s", len(nodes), truncateJSON(result, 300))
		findings = append(findings, f)
		fmt.Printf("  [MEDIUM] %d paired execution node(s) found\n", len(nodes))
	}

	return findings
}

func auditSecretsList(ws *utils.GatewayWSClient, tStr string) []utils.Finding {
	var findings []utils.Finding

	result, err := ws.Call("secrets.list", nil)
	if err != nil {
		return findings
	}

	var secrets []json.RawMessage
	if json.Unmarshal(result, &secrets) == nil && len(secrets) > 0 {
		f := utils.NewFinding(tStr, "audit",
			fmt.Sprintf("Secrets enumeration: %d secret entries", len(secrets)),
			utils.SevHigh,
			"secrets.list reveals configured secret references — potential credential exposure")
		f.Evidence = fmt.Sprintf("%d secrets: %s", len(secrets), truncateJSON(result, 300))
		f.Remediation = "Restrict secrets.list access or use scoped auth"
		findings = append(findings, f)
		fmt.Printf("  [HIGH] %d secret entries exposed via secrets.list\n", len(secrets))
	}

	return findings
}

func auditViaHTTP(target utils.Target, cfg AuditConfig) []utils.Finding {
	var findings []utils.Finding
	tStr := target.String()
	base := target.BaseURL()
	client := utils.HTTPClient(cfg.Timeout)

	// Check TLS
	if !target.UseTLS {
		// Try HTTPS to see if TLS is available
		tlsTarget := target
		tlsTarget.UseTLS = true
		status, _, _, err := utils.DoRequest(client, "GET", tlsTarget.BaseURL()+"/healthz", nil, nil)
		if err == nil && status == 200 {
			f := utils.NewFinding(tStr, "audit",
				"Gateway accessible over plain HTTP (TLS available but not enforced)",
				utils.SevMedium,
				"Gateway responds on HTTP while TLS is available — credentials transmitted in cleartext")
			f.Remediation = "Enforce TLS-only access or use SSH tunnel"
			findings = append(findings, f)
			fmt.Printf("  [MEDIUM] HTTP access while TLS is available\n")
		} else {
			f := utils.NewFinding(tStr, "audit",
				"Gateway uses plain HTTP (no TLS)",
				utils.SevMedium,
				"All traffic including tokens/passwords transmitted in cleartext")
			f.Remediation = "Enable TLS via gateway.tls or use reverse proxy with TLS"
			findings = append(findings, f)
			fmt.Printf("  [MEDIUM] No TLS — cleartext traffic\n")
		}
	}

	// Check security headers on control UI (try both single and double underscore)
	headers := map[string]string{}
	if cfg.Token != "" {
		headers["Authorization"] = "Bearer " + cfg.Token
	}
	// Try single underscore first (newer versions)
	status, _, respHeaders, err := utils.DoRequest(client, "GET", base+"/__openclaw/a2ui/", headers, nil)
	if err != nil || status == 404 {
		// Fallback to double underscore (older versions)
		status, _, respHeaders, err = utils.DoRequest(client, "GET", base+"/__openclaw__/a2ui/", headers, nil)
	}
	if err == nil && status == 200 {
		// Check CSP
		csp := respHeaders.Get("Content-Security-Policy")
		if csp == "" {
			f := utils.NewFinding(tStr, "audit",
				"No Content-Security-Policy header on Control UI",
				utils.SevMedium,
				"Control UI lacks CSP header — XSS risk increased")
			findings = append(findings, f)
			fmt.Printf("  [MEDIUM] Missing CSP header on Control UI\n")
		} else if strings.Contains(csp, "ws:") && strings.Contains(csp, "wss:") {
			f := utils.NewFinding(tStr, "audit",
				"CSP allows arbitrary WebSocket connections (ws: wss:)",
				utils.SevLow,
				"connect-src includes ws: and wss: — allows WS to any origin")
			f.Evidence = fmt.Sprintf("CSP: %s", csp)
			findings = append(findings, f)
		}

		// Check X-Frame-Options
		xfo := respHeaders.Get("X-Frame-Options")
		if xfo == "" && !strings.Contains(csp, "frame-ancestors") {
			f := utils.NewFinding(tStr, "audit",
				"No clickjacking protection on Control UI",
				utils.SevLow,
				"Missing X-Frame-Options and CSP frame-ancestors")
			findings = append(findings, f)
		}
	}

	return findings
}

func truncateJSON(data json.RawMessage, maxLen int) string {
	s := string(data)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
