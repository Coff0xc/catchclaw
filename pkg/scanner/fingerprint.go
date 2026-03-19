package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍FingerprintResult holds fingerprint detection results
type FingerprintResult struct {
	IsOpenClaw  bool   `json:"is_openclaw"`
	Version     string `json:"version,omitempty"`
	AuthMode    string `json:"auth_mode,omitempty"` // none, token, password, unknown
	BindMode    string `json:"bind_mode,omitempty"`
	HasCanvas   bool   `json:"has_canvas"`
	HasA2UI     bool   `json:"has_a2ui"`
	HasOpenAI   bool   `json:"has_openai_compat"`
	HasHooks    bool   `json:"has_hooks"`
	HealthOK    bool   `json:"health_ok"`
	ServerHeader string `json:"server_header,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
}

// Fingerprint performs OpenClaw instance detection and fingerprinting
func Fingerprint(target utils.Target, timeout time.Duration) (*FingerprintResult, []utils.Finding) {
	client := utils.HTTPClient(timeout)
	result := &FingerprintResult{}
	var findings []utils.Finding
	base := target.BaseURL()
	tStr := target.String()

	fmt.Printf("\n[*] Fingerprinting %s ...\n", tStr)

	// 1. Port connectivity check
	conn, err := net.DialTimeout("tcp", tStr, 5*time.Second)
	if err != nil {
		fmt.Printf("  [-] Port %d not reachable: %v\n", target.Port, err)
		return result, findings
	}
	conn.Close()
	fmt.Printf("  [+] Port %d is open\n", target.Port)

	// 2. Health endpoint probe
	for _, path := range []string{"/healthz", "/health", "/readyz", "/ready"} {
		status, body, headers, err := utils.DoRequest(client, "GET", base+path, nil, nil)
		if err != nil {
			continue
		}
		if status == 200 {
			result.HealthOK = true
			result.Endpoints = append(result.Endpoints, path)

			// extract server header
			if sv := headers.Get("Server"); sv != "" {
				result.ServerHeader = sv
			}

			// try parse health response for version info
			var healthResp map[string]interface{}
			if json.Unmarshal(body, &healthResp) == nil {
				if v, ok := healthResp["version"]; ok {
					result.Version = fmt.Sprintf("%v", v)
				}
			}

			fmt.Printf("  [+] Health endpoint %s → 200 OK\n", path)
			if result.Version != "" {
				fmt.Printf("  [+] Version detected: %s\n", result.Version)
			}
			break
		}
	}

	// 3. OpenAI compat endpoint probe
	status, chatBody, _, err := utils.DoRequest(client, "POST", base+"/v1/chat/completions",
		map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"model":"probe","messages":[]}`))
	if err == nil {
		result.Endpoints = append(result.Endpoints, "/v1/chat/completions")
		result.HasOpenAI = true
		// Filter out non-API responses (OAuth redirect landing, SPA fallback)
		isNonAPI := strings.Contains(string(chatBody), "<title>Sign-in</title>") ||
			strings.Contains(string(chatBody), "cognito") ||
			strings.Contains(string(chatBody), "oauth2/authorize") ||
			strings.Contains(string(chatBody), "openclaw-app") ||
			strings.Contains(string(chatBody), "<!doctype html") ||
			strings.Contains(string(chatBody), "<!DOCTYPE html")
		switch status {
		case 200:
			if isNonAPI {
				fmt.Printf("  [~] /v1/chat/completions → 200 (HTML response — redirect/SPA fallback, not real API)\n")
			} else {
				result.AuthMode = "none"
				result.IsOpenClaw = true
				f := utils.NewFinding(tStr, "fingerprint", "OpenAI compat endpoint accessible without auth",
					utils.SevCritical, "/v1/chat/completions returns 200 without Bearer token")
				f.Evidence = fmt.Sprintf("POST /v1/chat/completions → %d", status)
				findings = append(findings, f)
				fmt.Printf("  [!] /v1/chat/completions → %d (NO AUTH!)\n", status)
			}
		case 400:
			if isNonAPI {
				fmt.Printf("  [~] /v1/chat/completions → 400 (HTML response — not real API)\n")
			} else {
				// 400 = authenticated but bad request body → auth.mode=none
				result.AuthMode = "none"
				result.IsOpenClaw = true
				f := utils.NewFinding(tStr, "fingerprint", "OpenAI compat endpoint accessible without auth (400)",
					utils.SevCritical, "/v1/chat/completions returns 400 (no auth required, bad body)")
				f.Evidence = fmt.Sprintf("POST /v1/chat/completions → %d (no Bearer, got past auth)", status)
				findings = append(findings, f)
				fmt.Printf("  [!] /v1/chat/completions → %d (NO AUTH, bad body)\n", status)
			}
		case 401, 403:
			result.AuthMode = "token" // or password, will refine later
			result.IsOpenClaw = true
			fmt.Printf("  [+] /v1/chat/completions → %d (auth required)\n", status)
		default:
			fmt.Printf("  [?] /v1/chat/completions → %d\n", status)
		}
	}

	// 4. Control UI config probe (primary fingerprint)
	status, body, _, err := utils.DoRequest(client, "GET", base+"/__openclaw/control-ui-config.json", nil, nil)
	if err == nil && status == 200 {
		// Check if response is actual JSON config (not SPA fallback HTML)
		var configResp map[string]interface{}
		if json.Unmarshal(body, &configResp) == nil {
			// Real JSON config — confirmed OpenClaw
			result.IsOpenClaw = true
			result.Endpoints = append(result.Endpoints, "/__openclaw/control-ui-config.json")

			if v, ok := configResp["serverVersion"]; ok {
				result.Version = fmt.Sprintf("%v", v)
				fmt.Printf("  [+] OpenClaw detected via control-ui-config.json (version: %s)\n", result.Version)
			}

			f := utils.NewFinding(tStr, "fingerprint",
				"OpenClaw control-ui-config.json exposed",
				utils.SevInfo,
				fmt.Sprintf("/__openclaw/control-ui-config.json accessible (version: %s)", result.Version))
			f.Evidence = string(body)
			findings = append(findings, f)
		} else if strings.Contains(string(body), "openclaw-app") || strings.Contains(string(body), "OpenClaw Control") {
			// SPA fallback — HTML returned instead of JSON. Still confirms OpenClaw but not a real config leak.
			result.IsOpenClaw = true
			fmt.Printf("  [+] OpenClaw detected via SPA shell (control-ui-config.json returned HTML fallback)\n")
		}
	}

	// 5. Canvas / A2UI probe (both single and double underscore for compatibility)
	for _, path := range []string{"/__openclaw/canvas/", "/__openclaw__/canvas/", "/__openclaw/a2ui/", "/__openclaw__/a2ui/"} {
		status, body, _, err := utils.DoRequest(client, "GET", base+path, nil, nil)
		if err != nil {
			continue
		}
		// Detect SPA fallback — nginx returns 200 + HTML for all unmatched routes.
		// If a random sub-path also returns 200+HTML, this is fallback, not a real endpoint.
		bodyStr := string(body)
		isSPA := strings.Contains(bodyStr, "openclaw-app") || strings.Contains(bodyStr, "OPENCLAW_CONTROL_UI_BASE_PATH")
		isDoubleUnderscore := strings.Contains(path, "__openclaw__")
		if status == 200 && isSPA && isDoubleUnderscore {
			probePath := path + "__lobster_probe__"
			probeStatus, probeBody, _, probeErr := utils.DoRequest(client, "GET", base+probePath, nil, nil)
			if probeErr == nil && probeStatus == 200 && strings.Contains(string(probeBody), "openclaw-app") {
				// SPA fallback confirmed — not a real endpoint
				fmt.Printf("  [~] %s → SPA fallback (not real endpoint)\n", path)
				continue
			}
		}

		result.Endpoints = append(result.Endpoints, path)
		if strings.Contains(path, "/canvas/") {
			result.HasCanvas = status != 404
		} else {
			result.HasA2UI = status != 404
		}
		if status == 200 {
			result.IsOpenClaw = true
			sev := utils.SevMedium
			if isDoubleUnderscore && !isSPA {
				sev = utils.SevHigh
			}
			f := utils.NewFinding(tStr, "fingerprint",
				fmt.Sprintf("Canvas/A2UI path accessible: %s", path),
				sev,
				fmt.Sprintf("%s returns %d — web UI exposed", path, status))
			findings = append(findings, f)
			fmt.Printf("  [+] %s → %d (exposed)\n", path, status)
		} else if status != 404 {
			fmt.Printf("  [*] %s → %d\n", path, status)
		}
	}

	// 5. Hooks endpoint probe
	for _, path := range []string{"/hooks", "/hooks/"} {
		status, _, _, err := utils.DoRequest(client, "POST", base+path,
			map[string]string{"Content-Type": "application/json"},
			strings.NewReader(`{}`))
		if err != nil {
			continue
		}
		if status != 404 {
			result.HasHooks = true
			result.Endpoints = append(result.Endpoints, path)
			fmt.Printf("  [+] Hooks endpoint %s → %d\n", path, status)
			break
		}
	}

	// 6. Additional endpoint enumeration
	probePaths := []string{
		"/v1/responses",
		"/api/channels/mattermost/command",
	}
	for _, path := range probePaths {
		status, _, _, err := utils.DoRequest(client, "POST", base+path,
			map[string]string{"Content-Type": "application/json"},
			strings.NewReader(`{}`))
		if err != nil {
			continue
		}
		if status != 404 {
			result.Endpoints = append(result.Endpoints, path)
			fmt.Printf("  [*] %s → %d\n", path, status)
		}
	}

	if !result.IsOpenClaw {
		fmt.Printf("  [-] Target does not appear to be an OpenClaw instance\n")
	} else {
		fmt.Printf("  [+] Confirmed: OpenClaw instance detected\n")
	}

	return result, findings
}
