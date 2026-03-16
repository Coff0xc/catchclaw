package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// NoAuthCheck tests if the target has auth.mode=none
func NoAuthCheck(target utils.Target, timeout time.Duration) []utils.Finding {
	client := utils.HTTPClient(timeout)
	var findings []utils.Finding
	base := target.BaseURL()
	tStr := target.String()

	fmt.Printf("\n[*] Testing no-auth access on %s ...\n", tStr)

	// Test 1: /v1/chat/completions without any token
	status, body, _, err := utils.DoRequest(client, "POST", base+"/v1/chat/completions",
		map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"model":"probe","messages":[{"role":"user","content":"ping"}]}`))
	if err != nil {
		fmt.Printf("  [-] /v1/chat/completions unreachable: %v\n", err)
		return findings
	}

	switch {
	case status == 200:
		f := utils.NewFinding(tStr, "auth", "Gateway has NO authentication (auth.mode=none)",
			utils.SevCritical,
			"POST /v1/chat/completions succeeds without any Bearer token. Full operator access.")
		f.Evidence = fmt.Sprintf("HTTP %d — response body: %s", status, truncate(string(body), 200))
		f.Remediation = "Set gateway.auth.token or gateway.auth.password in openclaw.json"
		findings = append(findings, f)
		fmt.Printf("  [!!!] CRITICAL: No authentication! Full access confirmed.\n")

	case status == 400:
		// 400 means auth passed but request was malformed — still no auth
		f := utils.NewFinding(tStr, "auth", "Gateway has NO authentication (auth.mode=none, 400 on probe)",
			utils.SevCritical,
			"POST /v1/chat/completions returns 400 without Bearer token — auth layer is disabled.")
		f.Evidence = fmt.Sprintf("HTTP %d — body: %s", status, truncate(string(body), 200))
		f.Remediation = "Set gateway.auth.token or gateway.auth.password in openclaw.json"
		findings = append(findings, f)
		fmt.Printf("  [!!!] CRITICAL: No authentication! (400 = past auth, bad body)\n")

	case status == 401 || status == 403:
		fmt.Printf("  [+] Authentication is enabled (HTTP %d)\n", status)

	default:
		fmt.Printf("  [?] Unexpected status: %d\n", status)
	}

	// Test 2: WebSocket connect without token
	wsResult := testWsNoAuth(target, timeout)
	if wsResult != nil {
		findings = append(findings, *wsResult)
	}

	// Test 3: Canvas path without auth (both single and double underscore)
	for _, path := range []string{"/__openclaw/canvas/", "/__openclaw__/canvas/", "/__openclaw/a2ui/", "/__openclaw__/a2ui/"} {
		status, _, _, err := utils.DoRequest(client, "GET", base+path, nil, nil)
		if err != nil {
			continue
		}
		if status == 200 {
			f := utils.NewFinding(tStr, "auth",
				fmt.Sprintf("Canvas/A2UI accessible without auth: %s", path),
				utils.SevHigh,
				fmt.Sprintf("GET %s returns 200 without Bearer token", path))
			f.Evidence = fmt.Sprintf("HTTP %d", status)
			findings = append(findings, f)
			fmt.Printf("  [!] %s accessible without auth (HTTP 200)\n", path)
		}
	}

	// Test 4: Health/ready endpoints (info gathering, not vuln)
	for _, path := range []string{"/healthz", "/health"} {
		status, body, _, err := utils.DoRequest(client, "GET", base+path, nil, nil)
		if err != nil {
			continue
		}
		if status == 200 {
			var healthData map[string]interface{}
			if json.Unmarshal(body, &healthData) == nil {
				f := utils.NewFinding(tStr, "auth",
					"Health endpoint exposes instance info",
					utils.SevLow,
					fmt.Sprintf("GET %s returns instance metadata without auth", path))
				f.Evidence = truncate(string(body), 300)
				findings = append(findings, f)
			}
			break
		}
	}

	return findings
}

func testWsNoAuth(target utils.Target, timeout time.Duration) *utils.Finding {
	tStr := target.String()
	wsURL := target.WsURL()

	dialer := utils.WsDialer(timeout)
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			fmt.Printf("  [+] WebSocket requires auth (HTTP %d)\n", resp.StatusCode)
			return nil
		}
		fmt.Printf("  [-] WebSocket connect failed: %v\n", err)
		return nil
	}
	defer conn.Close()

	// If we connected without token, that's a problem
	f := utils.NewFinding(tStr, "auth", "WebSocket connects without authentication",
		utils.SevCritical,
		"WS connection established without any token — full control plane access")
	f.Evidence = fmt.Sprintf("Connected to %s without credentials", wsURL)
	f.Remediation = "Enable gateway.auth.token or gateway.auth.password"
	fmt.Printf("  [!!!] CRITICAL: WebSocket connected without auth!\n")
	return &f
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
