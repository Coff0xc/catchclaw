# Deep Audit: Supporting Modules (scanner / auth / recon / audit / discovery / utils)

Audit date: 2026-03-16
Auditor: Claude Opus 4.6 (code-reviewer)
Scope: Every `.go` file in 6 packages, brutally honest assessment

---

## Executive Summary

**Overall verdict: REAL, functional code with genuine OpenClaw-specific logic.**

Unlike many "security tools" that are thin wrappers around generic HTTP probes, this codebase demonstrates actual knowledge of OpenClaw's internal architecture: its WebSocket JSON-RPC protocol, specific configuration keys (`dangerouslyDisableDeviceAuth`, `allowInsecureAuth`), Canvas/A2UI paths, hook endpoints, and the full WS method namespace. The supporting modules are production-quality infrastructure, not stubs.

Key strengths:
- Genuine OpenClaw fingerprinting via platform-specific paths and behavior
- Real WebSocket JSON-RPC client with proper message ID correlation
- Brute force with working rate-limit backoff
- Configuration audit checks 15+ real OpenClaw config flags
- Shodan/FOFA integration with actual API calls and proper response parsing

Key weaknesses:
- No `rules/` directory exists -- wordlists are hardcoded inline
- Rate-limit detection makes a redundant HTTP request per loop iteration
- No password-mode brute force despite the `Method: "password"` field
- Version detection relies solely on `/healthz` JSON response
- Discovery defaults to port-only queries, not fingerprint-based

---

## 1. pkg/scanner/fingerprint.go -- Fingerprinting Engine

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\scanner\fingerprint.go` (179 lines)

### Does it actually detect OpenClaw instances?

**YES.** The fingerprinting logic uses 6 distinct probes, and the `IsOpenClaw` flag is set based on OpenClaw-specific behaviors, not generic HTTP responses.

### Fingerprinting techniques used:

| Technique | Evidence | OpenClaw-specific? |
|-----------|----------|--------------------|
| TCP port probe | Line 39: `net.DialTimeout("tcp", tStr, 5*time.Second)` | No -- generic connectivity check |
| Health endpoint | Line 48: probes `/healthz`, `/health`, `/readyz`, `/ready` | Partially -- `/healthz` is Kubernetes-common but OpenClaw uses it. Sets `IsOpenClaw=true` on 200 |
| OpenAI compat endpoint | Line 80: `POST /v1/chat/completions` with `{"model":"probe","messages":[]}` | **YES** -- this is OpenClaw's OpenAI-compatible gateway endpoint. Behavior-based detection: 200=no-auth, 400=no-auth(bad body), 401/403=auth-required |
| Canvas/A2UI paths | Line 114: probes `/__openclaw__/canvas/` and `/__openclaw__/a2ui/` | **YES** -- these are OpenClaw-internal UI mount paths with `__openclaw__` prefix |
| Hooks endpoint | Line 139: `POST /hooks` and `/hooks/` | **YES** -- OpenClaw's webhook intake endpoint |
| Additional endpoints | Line 155: `/v1/responses`, `/api/channels/mattermost/command` | **YES** -- OpenClaw's Responses API and Mattermost channel integration |

### Analysis:

The fingerprint is **genuinely OpenClaw-specific**. The `/__openclaw__/canvas/` and `/__openclaw__/a2ui/` paths are platform-unique namespace prefixes that would not appear on any other service. The combination of `/v1/chat/completions` behavior analysis + OpenClaw-specific paths creates a reliable signature.

**Status code interpretation is smart:**

```go
// Lines 86-110: Distinguishes auth modes by response code
case 200:
    result.AuthMode = "none"   // no auth at all
case 400:
    result.AuthMode = "none"   // past auth layer, bad body
case 401, 403:
    result.AuthMode = "token"  // auth required
```

This is correct -- a 400 on an OpenAI-compat endpoint means the request reached the handler (past auth), while 401/403 means auth blocked it.

### Issues found:

1. **Health endpoint sets IsOpenClaw too eagerly (Line 55-56).** Any service returning 200 on `/healthz` would be flagged as OpenClaw. Should require corroboration from at least one OpenClaw-specific path.

```go
// Line 53-56: Too permissive
if status == 200 {
    result.HealthOK = true
    result.IsOpenClaw = true  // <-- Any K8s service with /healthz passes this
```

2. **Version extraction is fragile.** Only checks for a `"version"` key in the health JSON (line 66). If OpenClaw changes its health response schema, version detection silently fails.

3. **Server header extraction is good** (line 59-61) but the header value is never used for fingerprinting decisions.

4. **No TLS probe.** The scanner does not try HTTPS if HTTP fails, or vice versa. Relies entirely on user-supplied `--tls` flag.

---

## 2. pkg/auth/ -- Authentication Testing

### 2a. no_auth.go -- No-Auth Detection

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\auth\no_auth.go` (134 lines)

**Verdict: SOLID.** Four-pronged no-auth detection covering HTTP, WebSocket, Canvas, and health endpoints.

| Test | What it does | Real? |
|------|-------------|-------|
| Test 1 (line 22) | `POST /v1/chat/completions` without Bearer | YES -- real auth probe |
| Test 2 (line 58) | WebSocket connect without token via `testWsNoAuth()` | YES -- uses `gorilla/websocket` dialer, checks HTTP 401/403 on handshake failure |
| Test 3 (line 64) | Canvas/A2UI paths without auth | YES -- checks both `/__openclaw__` UI paths |
| Test 4 (line 81) | Health endpoint info leak | YES -- checks if health returns parseable JSON metadata |

**WebSocket no-auth test is real** (lines 103-127):

```go
func testWsNoAuth(target utils.Target, timeout time.Duration) *utils.Finding {
    dialer := utils.WsDialer(timeout)
    conn, resp, err := dialer.Dial(wsURL, nil)
    if err != nil {
        if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
            // Auth is working
            return nil
        }
        return nil
    }
    defer conn.Close()
    // If we connected without token, that's a problem
    f := utils.NewFinding(tStr, "auth", "WebSocket connects without authentication", ...)
```

This correctly uses the gorilla/websocket library with a real TCP dial. It properly checks both the error path (401/403 in HTTP upgrade response) and the success path (connection established = no auth).

### 2b. brute.go -- Token Brute Force

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\auth\brute.go` (231 lines)

#### Does token brute-force actually work?

**YES**, with caveats.

**The brute force loop (lines 111-154) is real and functional:**

```go
for i, candidate := range candidates {
    // Try as Bearer token
    found, method := tryCredential(client, base, candidate)
    if found {
        result.Found = true
        result.Token = candidate
        result.Method = method
        // ...
        return result, findings
    }
```

**`tryCredential` (lines 167-178) sends actual HTTP requests:**

```go
func tryCredential(client *http.Client, base, cred string) (bool, string) {
    status, _, _, err := utils.DoRequest(client, "POST", base+"/v1/chat/completions",
        map[string]string{
            "Content-Type":  "application/json",
            "Authorization": "Bearer " + cred,
        },
        strings.NewReader(`{"model":"probe","messages":[]}`))
    if err == nil && (status == 200 || status == 400) {
        return true, "token"
    }
    return false, ""
}
```

#### Is there real smart delay/rate limiting logic?

**Partially.** There is rate-limit detection and backoff, but with a significant bug:

```go
// Lines 137-143: Rate limit handling
if isRateLimited(client, base, candidate) {
    rateLimitHits++
    if cfg.RespectLimit {
        waitTime := 65 * time.Second
        time.Sleep(waitTime)
    }
}
```

**BUG: `isRateLimited()` makes a SECOND HTTP request (lines 181-189) after `tryCredential()` already made one.** This doubles the request count per candidate AND uses the same credential that was just tested. The rate-limit check should be based on the response from `tryCredential()`, not a separate probe.

```go
func isRateLimited(client *http.Client, base, cred string) bool {
    status, _, _, err := utils.DoRequest(client, "POST", base+"/v1/chat/completions",
        // ... sends ANOTHER request with same cred
    return err == nil && status == 429
}
```

This means for every single candidate token, the tool sends 2 requests to `/v1/chat/completions`. With 25 default tokens, that is 50 requests instead of 25. Against a real rate limiter, this doubles the chance of triggering lockout.

**Additional delay logic (line 151):**

```go
if cfg.Delay > 0 {
    time.Sleep(cfg.Delay)
}
```

Default delay is 500ms. This is functional but basic -- no jitter, no exponential backoff, no adaptive timing based on response latency.

#### Where is the wordlist?

**There is NO `rules/` directory.** The glob search returned zero results for `rules/**/*`. The only wordlist is the inline `DefaultTokens` array (lines 15-42) with 25 entries:

```go
var DefaultTokens = []string{
    "change-me-to-a-long-random-token",  // OpenClaw default
    "openclaw", "OpenClaw",
    "test", "test123", "admin", "admin123",
    "password", "token", "secret", "123456",
    // ... 14 more generic weak passwords
}
```

The first entry `"change-me-to-a-long-random-token"` is the actual OpenClaw default token from its configuration template. The rest are generic weak passwords. The `--wordlist` flag allows loading external files, but no bundled wordlist file exists.

#### Other issues:

1. **No password-mode testing.** The `BruteResult.Method` field supports `"password"` (line 69), but `tryCredential()` only tests Bearer token auth (line 168-178). OpenClaw's `auth.mode=password` uses HTTP Basic Auth or a different mechanism, which is never tested.

2. **Pre-check is good** (lines 91-105): Confirms auth is required before bruting. Returns early if no-auth detected.

3. **Token masking works** (lines 225-230): `maskToken("admin123")` produces `ad****23`.

4. **Wordlist dedup is correct** (lines 191-222): Uses a `seen` map to prevent duplicate candidates.

---

## 3. pkg/recon/recon.go -- Reconnaissance

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\recon\recon.go` (398 lines)

### Does HTTP endpoint enumeration use OpenClaw-specific paths?

**YES.** The probe list (lines 38-65) contains 14 OpenClaw-specific endpoints:

```go
probes := []probe{
    // Health / readiness
    {"GET", "/healthz", ...},
    {"GET", "/health", ...},
    {"GET", "/readyz", ...},
    {"GET", "/ready", ...},
    // OpenAI compat
    {"POST", "/v1/chat/completions", `{"model":"probe","messages":[]}`, "OpenAI compat chat"},
    {"POST", "/v1/responses", `{"model":"probe","input":"probe"}`, "OpenAI responses"},
    // Canvas / A2UI
    {"GET", "/__openclaw__/canvas/", ...},
    {"GET", "/__openclaw__/a2ui/", ...},
    // Hooks
    {"POST", "/hooks", ...},
    {"POST", "/hooks/agent", ...},
    {"POST", "/hooks/wake", ...},
    // Channels
    {"POST", "/api/channels/mattermost/command", ...},
    // Plugin routes
    {"GET", "/__openclaw__/plugins/", ...},
    {"GET", "/api/slack/events", ...},
    {"GET", "/api/slack/oauth", ...},
}
```

These are real OpenClaw routes:
- `/__openclaw__/canvas/` and `/__openclaw__/a2ui/` are the web UI mount points
- `/hooks`, `/hooks/agent`, `/hooks/wake` are the webhook intake paths
- `/v1/responses` is OpenClaw's Responses API endpoint
- `/api/channels/mattermost/command` is the Mattermost slash command handler
- `/api/slack/events` and `/api/slack/oauth` are Slack integration routes

**Auth detection per-endpoint is well-implemented** (lines 84-90):

```go
if status == 401 || status == 403 {
    authStatus = "required"
} else if status == 404 {
    continue // endpoint doesn't exist
} else if status == 200 || status == 400 || status == 405 {
    authStatus = "none"
}
```

**Sensitive endpoint flagging** (lines 109-124) correctly identifies which unauthenticated endpoints are dangerous:

```go
sensitivePaths := map[string]bool{
    "/v1/chat/completions": true,
    "/v1/responses":       true,
    "/hooks":              true,
    "/hooks/agent":        true,
    "/hooks/wake":         true,
}
```

### Does WebSocket method discovery actually connect via WS and enumerate?

**YES. This is the most impressive part of the recon module.**

`EnumWSMethods()` (lines 148-353) connects via the `GatewayWSClient` (real WebSocket JSON-RPC) and systematically probes **55 distinct WS RPC methods** organized by category:

| Category | Methods | Count |
|----------|---------|-------|
| Core info | `config.get`, `config.set`, `config.openFile`, `health`, `system.info`, `system-event`, `gateway.identity.get`, `update.check`, `update.run` | 9 |
| Sessions | `sessions.list/preview/get/send/delete/fork/patch/compact` | 8 |
| Agents | `agents.list/create/update`, `agents.files.list/get/set` | 6 |
| Nodes/Devices | `nodes.list`, `devices.list/pair`, `node.invoke`, `node.pending.enqueue` | 5 |
| Tools | `tools.catalog/invoke/call/execute` | 4 |
| Files | `files.read/write/list`, `fs.read/write/list` | 6 |
| Browser | `browser.evaluate/navigate/screenshot/request` | 4 |
| Secrets | `secrets.list/get/export` | 3 |
| Models/Chat | `models.list`, `chat.history`, `talk.config` | 3 |
| Other | `cron.list/create`, `logs.query/list`, `exec.approvals.*`, `evaluate`, `skills.*`, `web.login.*`, `wizard.*`, `push.test`, `doctor.memory.status`, `wake` | 7+ |

**Method existence detection is smart** (lines 248-264):

```go
result, err := ws.Call(method, nil)
if err != nil {
    errStr := err.Error()
    if strings.Contains(errStr, "unknown method") ||
        strings.Contains(errStr, "not found") ||
        strings.Contains(errStr, "not implemented") {
        continue  // method does not exist
    }
    // Method exists but returned error (e.g. missing params)
    available = append(available, method+" (error: "+truncate(errStr, 60)+")")
```

This correctly distinguishes "method not found" (skip) from "method exists but bad params" (report as available). This is real JSON-RPC enumeration technique.

**Dangerous tool detection in `tools.catalog`** (lines 284-319) is excellent -- scans the catalog response for known dangerous tools:

```go
dangerousTools := []struct { name string; sev utils.Severity; desc string }{
    {"system.run", utils.SevCritical, "Arbitrary command execution"},
    {"bash", utils.SevCritical, "Shell command execution"},
    {"exec", utils.SevCritical, "Process execution"},
    {"fs.write", utils.SevHigh, "Arbitrary file write"},
    {"apply_patch", utils.SevHigh, "File write (path traversal risk)"},
    {"browser.evaluate", utils.SevHigh, "JavaScript eval in browser context"},
    {"computer_use", utils.SevCritical, "Full computer control"},
    {"mcp_", utils.SevMedium, "MCP tool (external integration)"},
}
```

### Is version detection real?

**Minimal but functional.** `VersionDetect()` (lines 356-391) only checks the `/healthz` JSON response for a `"version"` key:

```go
var health map[string]interface{}
if json.Unmarshal(body, &health) == nil {
    if v, ok := health["version"]; ok {
        version := fmt.Sprintf("%v", v)
```

**Weakness:** No fallback techniques. Could also extract version from:
- Server header (already captured but unused)
- `system.info` WS method (listed in EnumWSMethods but not used for version)
- Error messages that may include version strings
- `/__openclaw__/a2ui/` HTML/JS bundles containing version info

---

## 4. pkg/audit/audit.go -- Configuration Auditing

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\audit\audit.go` (382 lines)

### Are there actually 15+ audit items?

**YES. I count 18 distinct audit checks:**

#### WS-based checks (via `config.get`):

| # | Check | Config Key | Severity | Evidence |
|---|-------|-----------|----------|----------|
| 1 | `dangerouslyDisableDeviceAuth=true` | `gateway.controlUi.dangerouslyDisableDeviceAuth` | HIGH | Line 105 |
| 2 | `allowInsecureAuth=true` | `gateway.controlUi.allowInsecureAuth` | HIGH | Line 113 |
| 3 | `dangerouslyAllowHostHeaderOriginFallback=true` | `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback` | HIGH | Line 121 |
| 4 | `allowUnsafeExternalContent=true` | `hooks.gmail.allowUnsafeExternalContent` | HIGH | Line 129 |
| 5 | `workspaceOnly=false` on apply_patch | `tools.exec.applyPatch.workspaceOnly` | HIGH | Line 137 |
| 6 | Sandbox configuration presence | `agents.defaults.sandbox.mode` | INFO | Line 145 |
| 7 | `auth.mode=none` | `gateway.auth.mode` | CRITICAL | Line 153 |
| 8 | `bind=lan` | `gateway.bind` | HIGH | Line 161 |
| 9 | `dangerouslyAllowPrivateNetwork=true` (SSRF) | `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` | HIGH | Line 169 |
| 10 | Sandbox mode=off | sandbox.mode | HIGH | Line 191 |
| 11 | Wildcard origin `*` | `gateway.controlUi.allowedOrigins` | HIGH | Line 203 |

#### WS-based data exposure checks:

| # | Check | Method | Severity |
|---|-------|--------|----------|
| 12 | Session exposure | `sessions.list` | MEDIUM |
| 13 | Agent enumeration | `agents.list` | INFO |
| 14 | Paired nodes | `nodes.list` | MEDIUM |
| 15 | Secrets enumeration | `secrets.list` | HIGH |

#### HTTP-based checks:

| # | Check | Severity |
|---|-------|----------|
| 16 | TLS availability / enforcement | MEDIUM |
| 17 | Missing CSP header on Control UI | MEDIUM |
| 18 | Missing clickjacking protection (X-Frame-Options / frame-ancestors) | LOW |

Plus conditional sub-checks: CSP ws:/wss: allowance, TLS-available-but-not-enforced vs no-TLS-at-all.

### Does it check real OpenClaw configuration endpoints?

**YES.** Every configuration key in the audit is a real OpenClaw setting:

- `dangerouslyDisableDeviceAuth` -- real OpenClaw Gateway flag (the `dangerously` prefix is OpenClaw's naming convention for opt-in dangerous settings)
- `allowInsecureAuth` -- real flag that allows non-TLS authentication
- `dangerouslyAllowHostHeaderOriginFallback` -- real flag for CORS/origin bypass
- `allowUnsafeExternalContent` -- real hooks flag for external content processing
- `tools.exec.applyPatch.workspaceOnly` -- real path traversal protection flag
- `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` -- real SSRF protection flag

**Implementation approach** (lines 92-188): The audit retrieves the full config via `config.get` WS method, then performs substring matching on the JSON:

```go
configStr := string(result)
// ...
if strings.Contains(configStr, check.pattern) {
    f := utils.NewFinding(...)
```

**Weakness:** This is fragile. Substring matching like `strings.Contains(configStr, `"mode":"none"`)` could false-positive if `"mode":"none"` appears in an unrelated config section (e.g., a plugin config). Proper JSON path traversal would be more reliable. However, for the specific patterns checked, false positives are unlikely due to the uniqueness of the key names.

---

## 5. pkg/discovery/discovery.go -- Shodan/FOFA Integration

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\discovery\discovery.go` (211 lines)

### Does it actually call Shodan/FOFA APIs?

**YES.** Both functions make real HTTP GET requests to the official API endpoints.

**Shodan** (lines 37-98):

```go
apiURL := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&minify=true",
    url.QueryEscape(cfg.ShodanKey), url.QueryEscape(query))
// ...
resp, err := client.Get(apiURL)
```

- Correct API endpoint: `https://api.shodan.io/shodan/host/search`
- Uses `minify=true` for smaller responses
- Proper query parameter encoding with `url.QueryEscape`
- Parses real Shodan response structure: `total`, `matches[].ip_str`, `matches[].port`, `matches[].hostnames`, `matches[].version`
- Response body limit: 10MB (`io.LimitReader(resp.Body, 10<<20)`)

**FOFA** (lines 100-160):

```go
qb64 := base64.StdEncoding.EncodeToString([]byte(query))
apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d&fields=ip,port,host",
    url.QueryEscape(cfg.FofaEmail), url.QueryEscape(cfg.FofaKey), qb64, maxResults)
```

- Correct API endpoint: `https://fofa.info/api/v1/search/all`
- Proper base64 query encoding (FOFA requires this)
- Correct `fields=ip,port,host` parameter
- Parses FOFA response: `error`, `errmsg`, `size`, `results[][]`
- FOFA results are `[][]string` (array of arrays), correctly handled at line 148

### Are the search queries OpenClaw-specific?

**PARTIALLY.** Default queries are port-only:

```go
// Shodan default (line 43):
query = "port:18789"

// FOFA default (line 107):
query = `port="18789"`
```

Port 18789 is OpenClaw's default port, so this is minimally specific. However, many other services could run on this port. Better queries would include:

- Shodan: `port:18789 "openclaw"` or `port:18789 http.html:"__openclaw__"`
- FOFA: `port="18789" && body="openclaw"` or `port="18789" && header="openclaw"`

The `--query` flag allows custom queries, but the defaults lack fingerprint-level specificity.

### Deduplication is correct (lines 163-194):

```go
seen := make(map[string]bool)
key := fmt.Sprintf("%s:%d", r.IP, r.Port)
if seen[key] {
    continue
}
```

### WriteTargets (lines 198-204) produces a simple `host:port` file, compatible with the `-T` targets flag.

---

## 6. pkg/utils/ -- Utility Infrastructure

### 6a. http.go -- HTTP Client and Target

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\utils\http.go` (110 lines)

**HTTP client quality: GOOD for a security tool.**

```go
func HTTPClient(timeout time.Duration) *http.Client {
    return &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},  // Correct for pentesting
            MaxIdleConns:        50,
            MaxIdleConnsPerHost: 10,
            IdleConnTimeout:     30 * time.Second,
            DialContext: (&net.Dialer{
                Timeout:   5 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 3 { return fmt.Errorf("too many redirects") }
            return nil
        },
    }
}
```

Positives:
- `InsecureSkipVerify: true` is correct for a security scanner (targets may use self-signed certs)
- Connection pooling configured (50 idle, 10 per host)
- Redirect limit (3 max) prevents infinite loops
- 5-second dial timeout prevents hanging on unreachable targets

**`DoRequest` (lines 89-110) is clean:**
- Generic method/url/headers/body interface
- Response body limited to 1MB (`io.LimitReader(resp.Body, 1<<20)`)
- Custom User-Agent: `"LobsterGuard/1.0"` (line 98)
- Returns all four components: status, body, headers, error

**`ParseTarget` (lines 43-63) handles multiple input formats:**
- Strips `http://`, `https://`, `ws://`, `wss://` prefixes
- Falls back to port 18789 (OpenClaw default) when port is missing
- Uses `net.SplitHostPort` for proper parsing

### 6b. ws.go -- Basic WebSocket Dialer

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\utils\ws.go` (28 lines)

Thin wrapper around `gorilla/websocket`:

```go
func WsDialer(timeout time.Duration) *websocket.Dialer {
    return &websocket.Dialer{
        HandshakeTimeout: timeout,
        TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
    }
}
```

Clean and functional. `WsConnect` adds optional Bearer token in the HTTP upgrade headers.

### 6c. gateway_ws.go -- WebSocket JSON-RPC Client

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\utils\gateway_ws.go` (127 lines)

**Does the WS client actually implement WebSocket JSON-RPC?**

**YES.** This is a proper JSON-RPC client implementation.

**Protocol message structure (lines 22-33):**

```go
type WSMessage struct {
    ID     int             `json:"id,omitempty"`
    Method string          `json:"method,omitempty"`
    Params json.RawMessage `json:"params,omitempty"`
    Result json.RawMessage `json:"result,omitempty"`
    Error  *WSError        `json:"error,omitempty"`
}

type WSError struct {
    Code    int    `json:"code,omitempty"`
    Message string `json:"message,omitempty"`
}
```

This matches the JSON-RPC 2.0 pattern (id, method, params for requests; id, result/error for responses). OpenClaw's Gateway uses this exact protocol over WebSocket.

**Call() method (lines 68-109) has proper message correlation:**

```go
func (c *GatewayWSClient) Call(method string, params interface{}) (json.RawMessage, error) {
    c.mu.Lock()
    c.msgID++
    id := c.msgID
    c.mu.Unlock()

    msg := WSMessage{ID: id, Method: method, Params: paramsRaw}
    c.conn.WriteJSON(msg)

    // Read responses until we get our ID back
    for {
        var resp WSMessage
        c.conn.ReadJSON(&resp)
        if resp.ID == id {
            if resp.Error != nil {
                return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
            }
            return resp.Result, nil
        }
        // Skip push messages / events with different IDs
    }
}
```

Key implementation details:
- **Thread-safe message ID generation** via `sync.Mutex` (line 69-72)
- **Proper response correlation** by matching response ID to request ID (line 101)
- **Push message filtering** -- silently skips server-push events with different IDs (line 107)
- **Timeout enforcement** via `SetWriteDeadline` and `SetReadDeadline` (lines 89, 95)
- **Error propagation** from JSON-RPC error responses (lines 102-103)

**Origin header injection for CSWSH testing** (lines 41-64):

```go
func NewGatewayWSClientWithOrigin(target Target, token string, timeout time.Duration, origin string) (*GatewayWSClient, error) {
    headers := http.Header{}
    if origin != "" {
        headers.Set("Origin", origin)
    }
```

This enables the CORS bypass and WebSocket hijack exploit modules (Chain 13, Chain 17).

**CallRaw() (lines 112-120)** allows sending arbitrary raw bytes for fuzzing:

```go
func (c *GatewayWSClient) CallRaw(data []byte) ([]byte, error) {
    c.conn.WriteMessage(websocket.TextMessage, data)
    _, msg, err := c.conn.ReadMessage()
    return msg, err
}
```

### 6d. types.go -- Type Definitions

**File:** `E:\A-2026-project\Github-project\[AI龙虾安全]\lobster-guard\pkg\utils\types.go` (139 lines)

**Do the types match OpenClaw's actual API?**

The `Finding` struct is the tool's own reporting format, not an OpenClaw API type. The severity levels (INFO through CRITICAL) are standard security assessment practice.

The `ScanResult` struct aggregates findings per target with timing information -- straightforward and correct.

The `Banner()` function (lines 128-139) uses the `fatih/color` library for terminal coloring. The ASCII art banner is cosmetic but professional.

---

## Cross-Cutting Issues

### 1. No rules/ directory
The project claims to have wordlists in `rules/` but the directory does not exist. All token candidates are hardcoded in `brute.go:DefaultTokens`. External wordlists require the `--wordlist` flag.

### 2. Redundant HTTP request in brute force
`isRateLimited()` sends a duplicate request after every `tryCredential()` call. This is a functional bug that doubles request volume and increases lockout risk.

### 3. No password-mode brute force
`BruteResult.Method` supports `"password"` but `tryCredential()` only tests Bearer token auth. OpenClaw's password auth mode is never tested.

### 4. String-matching config audit
The `auditConfigGet()` function uses `strings.Contains()` on raw JSON to detect config patterns. While functional, this could false-positive on nested or unrelated config keys. JSON path traversal would be more reliable.

### 5. Discovery queries lack specificity
Default Shodan/FOFA queries use only port number (18789), which could match non-OpenClaw services. Adding content-based fingerprints would improve accuracy.

### 6. Version detection is single-source
Only `/healthz` JSON is checked for version info. The `system.info` WS method (which is already in the EnumWSMethods probe list) is a more reliable version source but is never used for this purpose.

### 7. WS client response loop has no escape hatch
`Call()` loops until it finds a matching ID or hits the read deadline. If the server floods push messages, this could block until timeout. A max-iterations guard would be safer.

---

## Verdict by Module

| Module | Real? | Quality | OpenClaw-specific? | Notes |
|--------|-------|---------|-------------------|-------|
| scanner/fingerprint.go | YES | 7/10 | YES | `/healthz` too eager; needs corroboration |
| auth/no_auth.go | YES | 9/10 | YES | 4-pronged detection including WS |
| auth/brute.go | YES | 6/10 | YES | Double-request bug; no password mode |
| recon/recon.go | YES | 9/10 | YES | 55 WS methods, tool catalog analysis |
| audit/audit.go | YES | 8/10 | YES | 18 real checks; string matching is fragile |
| discovery/discovery.go | YES | 8/10 | Partial | Real API calls; port-only default queries |
| utils/http.go | YES | 9/10 | N/A | Solid HTTP client with proper timeouts |
| utils/ws.go | YES | 8/10 | N/A | Clean gorilla/websocket wrapper |
| utils/gateway_ws.go | YES | 9/10 | YES | Real JSON-RPC with ID correlation, origin injection |
| utils/types.go | YES | 8/10 | N/A | Clean severity/finding model |

**Bottom line: This is legitimate, functional security tooling with genuine OpenClaw domain knowledge, not a facade. The recon and audit modules are particularly strong. The brute force module has a real but fixable bug. Infrastructure (utils/) is production-grade.**
