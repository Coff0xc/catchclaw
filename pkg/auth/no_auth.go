package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍NoAuthCheck tests if the target has auth.mode=none
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
		// Filter out non-API responses — redirect to OAuth/Cognito login page or SPA fallback
		bodyStr := string(body)
		if strings.Contains(bodyStr, "<title>Sign-in</title>") ||
			strings.Contains(bodyStr, "cognito") ||
			strings.Contains(bodyStr, "oauth2/authorize") ||
			strings.Contains(bodyStr, "openclaw-app") ||
			strings.Contains(bodyStr, "<!doctype html") ||
			strings.Contains(bodyStr, "<!DOCTYPE html") {
			fmt.Printf("  [~] /v1/chat/completions → 200 but response is HTML (redirect/SPA fallback, not real API)\n")
		} else {
			f := utils.NewFinding(tStr, "auth", "Gateway has NO authentication (auth.mode=none)",
				utils.SevCritical,
				"POST /v1/chat/completions succeeds without any Bearer token. Full operator access.")
			f.Evidence = fmt.Sprintf("HTTP %d — response body: %s", status, truncate(string(body), 200))
			f.Remediation = "Set gateway.auth.token or gateway.auth.password in openclaw.json"
			findings = append(findings, f)
			fmt.Printf("  [!!!] CRITICAL: No authentication! Full access confirmed.\n")
		}

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
	// Note: single-underscore paths (/__openclaw/) serve static frontend SPA assets
	// and are typically accessible by design. Double-underscore paths (/__openclaw__/)
	// serve the authenticated API. Only flag double-underscore as HIGH.
	for _, path := range []string{"/__openclaw/canvas/", "/__openclaw__/canvas/", "/__openclaw/a2ui/", "/__openclaw__/a2ui/"} {
		status, body, _, err := utils.DoRequest(client, "GET", base+path, nil, nil)
		if err != nil {
			continue
		}
		if status == 200 {
			isDoubleUnderscore := strings.Contains(path, "__openclaw__")
			// Check if response is just static HTML (SPA shell) vs actual API data
			bodyStr := string(body)
			isStaticSPA := strings.Contains(bodyStr, "<!doctype html") || strings.Contains(bodyStr, "<html") ||
				strings.Contains(bodyStr, "openclaw-app") || strings.Contains(bodyStr, "OPENCLAW_CONTROL_UI_BASE_PATH")

			// SPA fallback detection: if double-underscore path returns SPA HTML,
			// it's nginx fallback, NOT a real unauthenticated API endpoint.
			// Verify by checking a random sub-path — if it also returns 200+HTML, it's fallback.
			if isDoubleUnderscore && isStaticSPA {
				// Probe a random path under the same prefix to confirm SPA fallback
				probePath := path + "__lobster_probe_nonexistent__"
				probeStatus, probeBody, _, probeErr := utils.DoRequest(client, "GET", base+probePath, nil, nil)
				if probeErr == nil && probeStatus == 200 {
					probeStr := string(probeBody)
					if strings.Contains(probeStr, "openclaw-app") || strings.Contains(probeStr, "<!doctype html") {
						// Confirmed SPA fallback — not a real auth bypass
						sev := utils.SevInfo
						desc := fmt.Sprintf("GET %s returns SPA fallback (nginx catch-all) — not a real auth bypass", path)
						f := utils.NewFinding(tStr, "auth",
							fmt.Sprintf("Canvas/A2UI SPA fallback: %s", path),
							sev, desc)
						f.Evidence = fmt.Sprintf("HTTP %d (SPA fallback confirmed: random sub-path also returns 200+HTML)", status)
						findings = append(findings, f)
						fmt.Printf("  [~] %s is SPA fallback (not real auth bypass)\n", path)
						continue
					}
				}
				// Probe failed or returned different — might be real, keep HIGH
			}

			sev := utils.SevMedium
			desc := fmt.Sprintf("GET %s returns 200 without Bearer token — static frontend assets exposed (by design for single-underscore paths)", path)
			if isDoubleUnderscore {
				sev = utils.SevHigh
				desc = fmt.Sprintf("GET %s returns 200 without Bearer token — authenticated API path accessible without auth", path)
			}
			if isStaticSPA && !isDoubleUnderscore {
				sev = utils.SevInfo
				desc = fmt.Sprintf("GET %s returns frontend SPA shell without auth — static assets only, no API data", path)
			}

			f := utils.NewFinding(tStr, "auth",
				fmt.Sprintf("Canvas/A2UI accessible without auth: %s", path),
				sev, desc)
			f.Evidence = fmt.Sprintf("HTTP %d, body: %s", status, truncate(bodyStr, 150))
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

	// Use GatewayWSClient which properly detects challenge gate
	ws, err := utils.NewGatewayWSClient(target, "", timeout)
	if err != nil {
		fmt.Printf("  [-] WebSocket connect failed: %v\n", err)
		return nil
	}
	defer ws.Close()

	// If challenge gate is active, the server requires authentication —
	// WS handshake success alone does NOT mean unauthenticated access.
	if ws.HasChallengeGate() {
		fmt.Printf("  [+] WebSocket has challenge gate — auth required (nonce: %s)\n",
			utils.Truncate(ws.ChallengeID(), 16))
		return nil
	}

	// No challenge gate — try an actual RPC call to confirm full access
	result, callErr := ws.Call("health", nil)
	if callErr != nil {
		fmt.Printf("  [+] WebSocket connected but RPC calls fail: %v\n", callErr)
		// Connection succeeded but can't execute methods — not full access
		f := utils.NewFinding(tStr, "auth",
			"WebSocket accepts connection without auth but RPC calls fail",
			utils.SevMedium,
			"WS handshake succeeds without token but method calls are rejected — partial exposure")
		f.Evidence = fmt.Sprintf("Connected to %s, health call error: %v", target.WsURL(), callErr)
		return &f
	}

	// Full unauthenticated WS access confirmed
	f := utils.NewFinding(tStr, "auth", "WebSocket connects without authentication",
		utils.SevCritical,
		"WS connection established without any token AND RPC calls succeed — full control plane access")
	f.Evidence = fmt.Sprintf("Connected to %s without credentials, health returned: %s",
		target.WsURL(), utils.Truncate(string(result), 200))
	f.Remediation = "Enable gateway.auth.token or gateway.auth.password"
	fmt.Printf("  [!!!] CRITICAL: WebSocket full access without auth!\n")
	return &f
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
