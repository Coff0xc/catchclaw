package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// FingerprintResult holds fingerprint detection results
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
	status, _, _, err := utils.DoRequest(client, "POST", base+"/v1/chat/completions",
		map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"model":"probe","messages":[]}`))
	if err == nil {
		result.Endpoints = append(result.Endpoints, "/v1/chat/completions")
		result.HasOpenAI = true
		switch status {
		case 200:
			result.AuthMode = "none"
			result.IsOpenClaw = true
			f := utils.NewFinding(tStr, "fingerprint", "OpenAI compat endpoint accessible without auth",
				utils.SevCritical, "/v1/chat/completions returns 200 without Bearer token")
			f.Evidence = fmt.Sprintf("POST /v1/chat/completions → %d", status)
			findings = append(findings, f)
			fmt.Printf("  [!] /v1/chat/completions → %d (NO AUTH!)\n", status)
		case 400:
			// 400 = authenticated but bad request body → auth.mode=none
			result.AuthMode = "none"
			result.IsOpenClaw = true
			f := utils.NewFinding(tStr, "fingerprint", "OpenAI compat endpoint accessible without auth (400)",
				utils.SevCritical, "/v1/chat/completions returns 400 (no auth required, bad body)")
			f.Evidence = fmt.Sprintf("POST /v1/chat/completions → %d (no Bearer, got past auth)", status)
			findings = append(findings, f)
			fmt.Printf("  [!] /v1/chat/completions → %d (NO AUTH, bad body)\n", status)
		case 401, 403:
			result.AuthMode = "token" // or password, will refine later
			result.IsOpenClaw = true
			fmt.Printf("  [+] /v1/chat/completions → %d (auth required)\n", status)
		default:
			fmt.Printf("  [?] /v1/chat/completions → %d\n", status)
		}
	}

	// 4. Canvas / A2UI probe
	for _, path := range []string{"/__openclaw__/canvas/", "/__openclaw__/a2ui/"} {
		status, _, _, err := utils.DoRequest(client, "GET", base+path, nil, nil)
		if err != nil {
			continue
		}
		result.Endpoints = append(result.Endpoints, path)
		if path == "/__openclaw__/canvas/" {
			result.HasCanvas = status != 404
		} else {
			result.HasA2UI = status != 404
		}
		if status == 200 {
			result.IsOpenClaw = true
			f := utils.NewFinding(tStr, "fingerprint",
				fmt.Sprintf("Canvas/A2UI path accessible: %s", path),
				utils.SevMedium,
				fmt.Sprintf("%s returns %d — web UI exposed", path, status))
			findings = append(findings, f)
			fmt.Printf("  [+] %s → %d (exposed)\n", path, status)
		} else {
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
