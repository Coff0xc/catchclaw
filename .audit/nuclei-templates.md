# Nuclei Templates Deep Audit Report

**Project**: LobsterGuard
**Scope**: `nuclei-templates/` directory -- all 23 YAML files
**Auditor**: Claude Opus 4.6 (code-reviewer)
**Date**: 2026-03-16

---

## 1. File Inventory

Claimed count: **23**
Actual file count: **23** (verified)

| # | Filename | Size | Severity | Protocol |
|---|----------|------|----------|----------|
| 1 | openclaw-agent-files.yaml | 658B | medium | HTTP |
| 2 | openclaw-browser-cdp.yaml | 619B | high | HTTP |
| 3 | openclaw-canvas-exposed.yaml | 409B | medium | HTTP |
| 4 | openclaw-cors-misconfig.yaml | 550B | high | HTTP |
| 5 | openclaw-default-token.yaml | 643B | critical | HTTP |
| 6 | openclaw-detect.yaml | 612B | info | HTTP |
| 7 | openclaw-discord-interactions.yaml | 649B | medium | HTTP |
| 8 | openclaw-exec-approvals.yaml | 677B | high | HTTP |
| 9 | openclaw-full-rce.yaml | 1203B | critical | WebSocket |
| 10 | openclaw-hooks-no-auth.yaml | 705B | high | HTTP |
| 11 | openclaw-mattermost-inject.yaml | 746B | high | HTTP |
| 12 | openclaw-no-auth.yaml | 700B | critical | HTTP |
| 13 | openclaw-oauth-redirect.yaml | 654B | medium | HTTP |
| 14 | openclaw-openai-compat.yaml | 504B | info | HTTP |
| 15 | openclaw-plugin-traversal.yaml | 709B | high | HTTP |
| 16 | openclaw-responses-api.yaml | 697B | medium | HTTP |
| 17 | openclaw-rogue-node.yaml | 829B | critical | WebSocket |
| 18 | openclaw-secrets-resolve.yaml | 675B | critical | WebSocket |
| 19 | openclaw-sessions-exposed.yaml | 689B | medium | HTTP |
| 20 | openclaw-slack-no-signature.yaml | 776B | high | HTTP |
| 21 | openclaw-transcript-theft.yaml | 1117B | high | HTTP |
| 22 | openclaw-weak-tokens.yaml | 943B | high | HTTP |
| 23 | openclaw-ws-no-auth.yaml | 486B | critical | WebSocket |

Severity distribution: 5 Critical, 8 High, 6 Medium, 2 Info, 0 Low

---

## 2. Per-Template Detailed Analysis

---

### 2.1 `openclaw-detect.yaml` -- OpenClaw Gateway Detection

**Severity**: info
**Verdict**: WEAK -- generic fingerprint, easily produces false positives

```yaml
matchers-condition: and
matchers:
  - type: status
    status:
      - 200
  - type: word
    part: header
    words:
      - "application/json"
```

**Problems**:
- Matching `status: 200` + `application/json` header on `/healthz` is extremely generic. Literally any API that returns JSON on a health endpoint will match.
- The JSON extractor (`.version`) is good in theory, but it does not participate in matching -- it only extracts. The template will trigger on ANY JSON-returning health endpoint.
- A proper OpenClaw fingerprint should match a specific response body pattern, e.g. a known field like `"service":"openclaw-gateway"` or a specific header like `X-OpenClaw-Version`.
- The Shodan/FOFA metadata (`port:18789`) is useful context but does not improve detection accuracy.

**Would it work against real OpenClaw?** Yes, but it would also fire on thousands of non-OpenClaw targets. High false positive rate.

---

### 2.2 `openclaw-openai-compat.yaml` -- OpenAI Compatible API Detection

**Severity**: info
**Verdict**: USELESS -- matches any HTTP server

```yaml
matchers:
  - type: status
    status:
      - 400
      - 401
      - 403
      - 200
```

**Problems**:
- The matcher accepts status 200, 400, 401, or 403. That is essentially "any HTTP response that is not a 404 or 5xx."
- No body or header matching at all. Hitting `/v1/chat/completions` on any server that returns a non-404 response will trigger this.
- No `matchers-condition: and` with a body check. This is a status-code-only matcher.
- This is not a detection template; it is an HTTP-alive check disguised as OpenClaw detection.

**Would it work against real OpenClaw?** Yes, but it would also match literally any API gateway, reverse proxy, or web server that does not return 404 on these paths.

---

### 2.3 `openclaw-canvas-exposed.yaml` -- Canvas/A2UI Exposed

**Severity**: medium
**Verdict**: WEAK -- status-code-only matcher

```yaml
matchers:
  - type: status
    status:
      - 200
```

**Problems**:
- Only checks for HTTP 200 on `/__openclaw__/canvas/` and `/__openclaw__/a2ui/`. No body content matching.
- While the `__openclaw__` path prefix is somewhat specific, any web server that returns 200 on an unknown path (many do) could trigger this.
- Should check for specific HTML content, page title, or JavaScript references that identify the Canvas/A2UI interface.
- Missing: `matchers-condition: and` with a word/regex matcher for OpenClaw-specific content.

**Would it work against real OpenClaw?** Somewhat -- the path is specific enough to reduce false positives, but confirmation requires body matching.

---

### 2.4 `openclaw-no-auth.yaml` -- Gateway No Authentication

**Severity**: critical
**Verdict**: FUNDAMENTALLY FLAWED -- cannot distinguish "no auth" from "auth disabled" vs "valid request"

```yaml
matchers-condition: or
matchers:
  - type: status
    status:
      - 200
  - type: status
    status:
      - 400
```

**Problems**:
- This sends a POST to `/v1/chat/completions` with no Authorization header. If it gets 200 or 400, it considers authentication disabled.
- But status 400 could mean the server requires auth but has a bad request body parsing error. Many API frameworks return 400 for malformed JSON before checking auth.
- Status 200 without auth is more meaningful, but still -- without checking the body for an actual model response vs. an error message, it is unreliable.
- The matcher uses `matchers-condition: or` between two status checks that are logically very different (200 = success, 400 = error). These should not be OR'd together as equivalent "no auth" signals.
- Compare to `openclaw-default-token.yaml` below -- nearly identical logic, creating redundancy.

**Would it work against real OpenClaw?** Partially. A 200 response without auth is a genuine signal, but the 400 branch creates false positives.

---

### 2.5 `openclaw-default-token.yaml` -- Default Token Detection

**Severity**: critical
**Verdict**: PARTIALLY EFFECTIVE but flawed matcher logic

```yaml
headers:
  Authorization: "Bearer change-me-to-a-long-random-token"
body: '{"model":"probe","messages":[]}'
matchers-condition: or
matchers:
  - type: status
    status:
      - 200
  - type: status
    name: past-auth-bad-body
    status:
      - 400
```

**Problems**:
- The idea is sound: test the `.env.example` default token `change-me-to-a-long-random-token`. If the server accepts it, the default credential is in use.
- However, status 400 is matched as success ("past-auth-bad-body"), which assumes that a 400 means "auth passed but body was invalid." This is a dangerous assumption -- 400 can mean many things.
- If the server rejects the token with 401/403, the template correctly does NOT match. But a 400 from a completely unrelated issue would be a false positive.
- The overlap with `openclaw-weak-tokens.yaml` is significant -- that template also tests `change-me-to-a-long-random-token` as the first payload.

**Would it work against real OpenClaw?** Yes for the 200 case. The 400 case is ambiguous.

---

### 2.6 `openclaw-weak-tokens.yaml` -- Weak Token Brute Force

**Severity**: high
**Verdict**: BEST TEMPLATE IN THE SET -- proper payload-based fuzzing

```yaml
attack: sniper
payloads:
  token:
    - change-me-to-a-long-random-token
    - openclaw
    - OpenClaw
    - test
    - test123
    - admin
    - admin123
    - password
    - token
    - secret
    - 123456
    - default
    - gateway
    - lobster
    - demo
    - changeme
stop-at-first-match: true
```

**Problems**:
- This is the most sophisticated template in the set. It uses Nuclei's `sniper` attack type with parameter injection via `Bearer {{token}}` (using the `section sign` delimiter).
- `stop-at-first-match: true` is good for efficiency.
- However, the matcher still has the same 200/400 OR problem as the default-token template.
- The payload list is reasonable but small (16 tokens). Could benefit from a wordlist file reference.
- **DUPLICATE OVERLAP**: First payload `change-me-to-a-long-random-token` is the exact same test as `openclaw-default-token.yaml`. Running both templates is redundant.

**Would it work against real OpenClaw?** Yes, this is one of the few templates that would genuinely detect a real misconfiguration.

---

### 2.7 `openclaw-ws-no-auth.yaml` -- WebSocket No Auth

**Severity**: critical
**Verdict**: REASONABLE but minimally specified

```yaml
websocket:
  - address: "{{Host}}:{{Port}}"
    inputs:
      - data: '{"id":1,"method":"health"}'
    matchers:
      - type: word
        words:
          - '"result"'
          - '"id":1'
        condition: and
```

**Problems**:
- This tests a WebSocket connection to `/` on the target host:port, sending a JSON-RPC style health message.
- Matching both `"result"` and `"id":1` is decent -- it confirms a JSON-RPC response.
- However, the `method: "health"` call is not OpenClaw-specific. Any JSON-RPC service that responds to unknown methods with `"result"` would match.
- Missing: no `path` in the address -- should probably be `{{Host}}/gateway` to match the OpenClaw WebSocket endpoint (as used in other WS templates).
- The address format `{{Host}}:{{Port}}` is inconsistent with other WS templates that use `{{Host}}/gateway`.

**Would it work against real OpenClaw?** Yes, but only if the default port is targeted. The missing `/gateway` path may cause connection failures.

---

### 2.8 `openclaw-cors-misconfig.yaml` -- CORS Misconfiguration

**Severity**: high
**Verdict**: CORRECT TECHNIQUE but generic vulnerability class

```yaml
headers:
  Origin: "https://evil.com"
matchers-condition: and
matchers:
  - type: word
    part: header
    words:
      - "Access-Control-Allow-Origin: https://evil.com"
  - type: status
    status:
      - 200
```

**Problems**:
- The CORS origin reflection check is technically correct. Sending `Origin: https://evil.com` and checking if the response reflects it in `Access-Control-Allow-Origin` is the standard test.
- However, this is a completely generic CORS test. It has nothing OpenClaw-specific about it except the path `/healthz`.
- The word matcher checks the full header line as a string in the header part, which may fail depending on how Nuclei parses response headers (case sensitivity, whitespace).
- This same template could be applied to any web application. It is a generic web security check rebranded for OpenClaw.

**Would it work against real OpenClaw?** Yes, but it is not OpenClaw-specific. This is a standard CORS check.

---

### 2.9 `openclaw-plugin-traversal.yaml` -- Plugin Path Traversal

**Severity**: high
**Verdict**: CORRECT TECHNIQUE but likely will not work due to URL normalization

```yaml
path:
  - "{{BaseURL}}/__openclaw__/plugins/../../../etc/passwd"
  - "{{BaseURL}}/__openclaw__/plugins/..%2F..%2F..%2Fetc%2Fpasswd"
  - "{{BaseURL}}/__openclaw__/plugins/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
matchers:
  - type: word
    part: body
    words:
      - "root:"
      - "/bin/bash"
      - "/bin/sh"
    condition: or
```

**Problems**:
- The path traversal variants (raw `../`, URL-encoded `%2F`, double-encoded) are standard and appropriate.
- Body matching for `root:` and shell paths is the standard LFI confirmation.
- However, most HTTP clients and servers normalize `../` sequences in URLs before they reach the application. Nuclei's HTTP client may also normalize. The raw `../` variant will likely never reach the server as-is.
- The `__openclaw__/plugins/` path prefix is plausible but needs verification against actual OpenClaw source. If OpenClaw does not serve static files from a `plugins/` path, this is entirely fabricated.
- No Windows path traversal variants (e.g., `..\..\windows\win.ini`). Since many OpenClaw instances could run on Windows (the project itself appears to target Windows users), this is a gap.

**Would it work against real OpenClaw?** Unlikely. URL normalization would defeat the raw variant, and the encoded variants depend on the specific web server behavior.

---

### 2.10 `openclaw-oauth-redirect.yaml` -- OAuth Open Redirect

**Severity**: medium
**Verdict**: CORRECT TECHNIQUE but assumes Slack integration path exists

```yaml
path:
  - "{{BaseURL}}/api/slack/oauth?redirect_uri=https://evil.com/callback"
  - "{{BaseURL}}/api/slack/oauth/callback?redirect_uri=https://evil.com/callback"
matchers:
  - type: status
    status:
      - 301
      - 302
      - 303
      - 307
      - 308
  - type: word
    part: header
    words:
      - "evil.com"
```

**Problems**:
- Checking for redirect status codes and `evil.com` in the Location header is the correct open redirect test.
- The paths `/api/slack/oauth` and `/api/slack/oauth/callback` assume OpenClaw has a Slack OAuth integration. This needs verification.
- The `redirect_uri` parameter name is standard for OAuth, so the technique is sound.
- Good use of `matchers-condition: and` to require both redirect status and the evil domain in the header.

**Would it work against real OpenClaw?** Only if the Slack OAuth integration exists and has this specific vulnerability. The technique is correct.

---

### 2.11 `openclaw-slack-no-signature.yaml` -- Slack Events No Signature

**Severity**: high
**Verdict**: GOOD CONCEPT, decent implementation

```yaml
path:
  - "{{BaseURL}}/api/slack/events"
body: '{"type":"event_callback","event":{"type":"message","text":"nuclei_probe","user":"U123","channel":"C123"}}'
matchers:
  - type: status
    status:
      - 200
      - 201
      - 202
  - type: word
    part: body
    negative: true
    words:
      - "invalid signature"
      - "unauthorized"
```

**Problems**:
- The idea is excellent: send a Slack event callback without the `X-Slack-Signature` header. If the server accepts it (200/201/202 without "invalid signature" or "unauthorized" in body), signature validation is missing.
- The negative word matcher is a good technique -- checking that rejection messages are NOT present.
- However, this is subtly flawed: `negative: true` on a word matcher with `matchers-condition: and` means the template triggers when status is 200-202 AND the body does NOT contain those error words. But an empty 200 response (e.g., from a reverse proxy that swallows the request) would also match.
- The Slack event payload structure is authentic (`event_callback` type with `message` event).

**Would it work against real OpenClaw?** Yes, if the Slack integration endpoint exists. One of the better templates.

---

### 2.12 `openclaw-discord-interactions.yaml` -- Discord Interactions

**Severity**: medium
**Verdict**: WEAK -- overly generic matcher

```yaml
body: '{"type":1}'
matchers:
  - type: word
    part: body
    words:
      - "type"
```

**Problems**:
- Sends a Discord ping (type 1) to the interaction endpoints. Correct Discord protocol behavior.
- But matching only the word `"type"` in the response body is absurdly generic. Any JSON API response containing the key "type" would match.
- Should specifically check for `"type":1` in the response (Discord ping/pong) or `"type": 1`.
- The status matcher (200/201) combined with body containing "type" would fire on countless non-Discord endpoints.

**Would it work against real OpenClaw?** The request is correct, but the matcher is too loose to be meaningful.

---

### 2.13 `openclaw-mattermost-inject.yaml` -- Mattermost Command Injection

**Severity**: high
**Verdict**: WEAK -- same generic matcher problem

```yaml
body: "token=openclaw&text=nuclei_probe&user_name=nuclei&command=%2Fopenclaw"
matchers:
  - type: word
    part: body
    words:
      - "text"
      - "response"
    condition: or
```

**Problems**:
- Sends a Mattermost slash command payload with `token=openclaw` (hardcoded).
- Matching on body containing "text" or "response" is incredibly generic. Almost any JSON/text API response would match.
- The real test should be: does the server accept the command without validating the Mattermost token? The matcher should look for Mattermost-specific response format like `{"response_type":"in_channel"}`.
- The token `openclaw` is a guess; Mattermost outgoing webhooks have configurable tokens.

**Would it work against real OpenClaw?** The concept is valid, but the matcher would produce massive false positives.

---

### 2.14 `openclaw-hooks-no-auth.yaml` -- Hooks No Auth

**Severity**: high
**Verdict**: DECENT -- negative matching is correct approach

```yaml
matchers-condition: and
matchers:
  - type: status
    status:
      - 200
      - 202
  - type: word
    negative: true
    words:
      - "unauthorized"
      - "forbidden"
```

**Problems**:
- Tests three webhook paths (`/hooks/agent`, `/hooks/wake`, `/hooks`) with a simple JSON body.
- The negative matching approach (accept if no "unauthorized"/"forbidden" in response) is the right idea.
- However, any server that returns 200/202 without those specific words would match. A custom 403 page with different wording, or a 200 from a different service, would be a false positive.
- The paths `/hooks/agent` and `/hooks/wake` are plausible OpenClaw endpoints if the platform supports agent wake/trigger webhooks.

**Would it work against real OpenClaw?** Yes, if the hook endpoints exist. Moderate confidence.

---

### 2.15 `openclaw-agent-files.yaml` -- Agent Files Exposed

**Severity**: medium
**Verdict**: GOOD -- OpenClaw-specific matcher words

```yaml
path:
  - "{{BaseURL}}/__openclaw__/a2ui/api/agents/files/list"
matchers:
  - type: word
    part: body
    words:
      - "CLAUDE.md"
      - "AGENTS.md"
      - "IDENTITY.md"
    condition: or
```

**Problems**:
- The endpoint `/__openclaw__/a2ui/api/agents/files/list` is specific to OpenClaw's A2UI API.
- Checking for `CLAUDE.md`, `AGENTS.md`, `IDENTITY.md` in the response is excellent -- these are Claude Code / OpenClaw specific filenames that would not appear in other contexts.
- The `matchers-condition: and` with status 200 and body content is correct.
- One concern: these files (CLAUDE.md, AGENTS.md) are Claude Code conventions, not necessarily OpenClaw-specific. The conflation of Claude Code workspace files with OpenClaw may indicate the author is confused about the boundary between Claude Code (the IDE extension) and OpenClaw (the self-hosted platform).

**Would it work against real OpenClaw?** Yes. This is one of the better templates with meaningful, specific matchers.

---

### 2.16 `openclaw-exec-approvals.yaml` -- Exec Approvals Exposed

**Severity**: high
**Verdict**: GOOD -- specific endpoint and meaningful matchers

```yaml
path:
  - "{{BaseURL}}/__openclaw__/a2ui/api/exec/approvals"
matchers:
  - type: word
    part: body
    words:
      - "allowAll"
      - "approvals"
      - "rules"
    condition: or
```

**Problems**:
- The endpoint is highly specific to OpenClaw's execution approval system.
- The matcher words (`allowAll`, `approvals`, `rules`) are relevant to execution policy configuration.
- `condition: or` means any ONE of these words triggers a match. While `approvals` alone might be too generic, `allowAll` is specific enough to be meaningful.
- Could be stronger with `condition: and` requiring at least two words.

**Would it work against real OpenClaw?** Yes, with reasonable confidence.

---

### 2.17 `openclaw-sessions-exposed.yaml` -- Sessions Data Exposed

**Severity**: medium
**Verdict**: DECENT -- specific endpoint, reasonable matchers

```yaml
path:
  - "{{BaseURL}}/__openclaw__/a2ui/api/sessions/list"
matchers:
  - type: word
    part: body
    words:
      - "sessionId"
      - "agentId"
      - "transcript"
      - "sessions"
    condition: or
```

**Problems**:
- Endpoint is OpenClaw-specific (`/__openclaw__/a2ui/api/sessions/list`).
- Words like `sessionId` and `agentId` are specific to OpenClaw's session model.
- `sessions` alone is too generic as a matcher word.
- **DUPLICATE OVERLAP**: This template is nearly identical to the first request in `openclaw-transcript-theft.yaml` (same endpoint, same method, overlapping matchers).

**Would it work against real OpenClaw?** Yes.

---

### 2.18 `openclaw-transcript-theft.yaml` -- Session Transcript Theft

**Severity**: high
**Verdict**: GOOD CONCEPT but structurally problematic

```yaml
# Request 1: List sessions
- method: POST
  path:
    - "{{BaseURL}}/__openclaw__/a2ui/api/sessions/list"
  matchers:
    - type: word
      words:
        - "sessionId"
        - "key"
        - "sessionKey"
      condition: or

# Request 2: Get session data
- method: POST
  path:
    - "{{BaseURL}}/__openclaw__/a2ui/api/sessions/get"
  body: '{"limit":100}'
  matchers:
    - type: word
      words:
        - "messages"
        - "transcript"
        - "content"
      condition: or
```

**Problems**:
- Two-stage attack: list sessions, then get session data. The concept of chaining is correct.
- However, in Nuclei's HTTP protocol, multiple request blocks are independent -- the second request does NOT use data from the first. There is no session ID extraction and injection.
- The template claims "Session Transcript Theft" but does not actually steal a specific session's transcript. It just checks if `/sessions/get` returns any data.
- The body `{"limit":100}` is sent without a session ID, which would likely return an error or nothing on a real implementation.
- **DUPLICATE**: Request 1 overlaps with `openclaw-sessions-exposed.yaml`.

**Would it work against real OpenClaw?** Only partially. The chaining is fake -- the two requests are independent.

---

### 2.19 `openclaw-browser-cdp.yaml` -- Browser CDP Exposed

**Severity**: high
**Verdict**: CORRECT TECHNIQUE but not OpenClaw-specific

```yaml
path:
  - "{{BaseURL}}:9222/json/version"
  - "{{BaseURL}}:9222/json/list"
matchers:
  - type: word
    part: body
    words:
      - "webSocketDebuggerUrl"
      - "Browser"
      - "devtoolsFrontendUrl"
    condition: or
```

**Problems**:
- Checking for exposed Chrome DevTools Protocol on port 9222 is a well-known security check.
- The matchers are correct -- `webSocketDebuggerUrl` is the definitive CDP indicator.
- **However, this is not OpenClaw-specific at all.** Port 9222 CDP exposure is a generic container/debugging misconfiguration. Thousands of exposed CDP endpoints exist that have nothing to do with OpenClaw.
- The `{{BaseURL}}:9222` syntax is questionable -- `{{BaseURL}}` already includes the scheme and host. Appending `:9222` would create `http://host:port:9222/json/version`, which is an invalid URL. This template may not even execute correctly.
- This is a standard security check from public Nuclei template repositories, repackaged.

**Would it work against real OpenClaw?** The URL construction is likely broken. Even if fixed, it is a generic CDP check, not OpenClaw-specific.

---

### 2.20 `openclaw-full-rce.yaml` -- Full RCE Chain

**Severity**: critical
**Verdict**: AMBITIOUS CONCEPT but structurally broken

```yaml
websocket:
  - address: "{{Host}}/gateway"
    inputs:
      - data: '{"jsonrpc":"2.0","id":1,"method":"nodes.list","params":null}'
    matchers:
      - type: word
        words: ["nodeId", "platform", "commands"]
        condition: or
      - type: negative
        words: ["unknown method", "unauthorized"]

  - address: "{{Host}}/gateway"
    inputs:
      - data: '{"jsonrpc":"2.0","id":2,"method":"exec.approval.request","params":{"command":"echo nuclei_rce_probe","nodeId":"*","host":"node","twoPhase":true}}'
    matchers:
      - type: word
        words: ["id", "approval"]
        condition: or
      - type: negative
        words: ["unknown method"]
```

**Problems**:
- This claims to test a full RCE chain: `nodes.list` -> `exec.approval.request` -> self-approve -> `node.invoke system.run`.
- **Critical structural flaw**: In Nuclei's WebSocket protocol, multiple request blocks are independent connections. The second WebSocket connection does not carry state from the first. The "chain" is an illusion -- each block is a separate test.
- The template only has 2 of the 4 claimed chain steps. There is no `exec.approval.resolve` (self-approve) or `node.invoke` step.
- The matcher for the second request matching "id" is absurdly generic -- every JSON-RPC response contains "id".
- `type: negative` is not a standard Nuclei matcher type. The correct syntax is `negative: true` on a `type: word` matcher. This may cause Nuclei to reject the template at parse time.
- The `nodeId: "*"` wildcard in the RCE params is a guess -- real implementations would require a specific node ID extracted from step 1.

**Would it work against real OpenClaw?** No. The chain is broken by design, the negative matcher syntax may be invalid, and only 2 of 4 steps are implemented.

---

### 2.21 `openclaw-rogue-node.yaml` -- Rogue Node Registration

**Severity**: critical
**Verdict**: INTERESTING CONCEPT, flawed execution

```yaml
inputs:
  - data: '{"jsonrpc":"2.0","id":1,"method":"node.pair.request","params":{"nodeId":"nuclei-probe","displayName":"Nuclei Probe","platform":"linux","commands":["system.run"],"caps":["exec"]}}'
matchers:
  - type: word
    words: ["pairingCode", "pairingId", "id"]
    condition: or
  - type: negative
    words: ["unknown method", "not found", "unauthorized"]
```

**Problems**:
- The concept of testing rogue node registration is excellent and specific to OpenClaw's architecture.
- The JSON-RPC method `node.pair.request` with appropriate params is well-crafted.
- Matching for `pairingCode` or `pairingId` is specific and meaningful.
- However, `"id"` in the `condition: or` list undermines the matcher -- every JSON-RPC response has `"id"`.
- Same `type: negative` syntax issue as `openclaw-full-rce.yaml` -- likely invalid Nuclei syntax.
- The pairing request would likely require additional approval steps in a real OpenClaw deployment, so even a successful match does not mean rogue registration succeeded.

**Would it work against real OpenClaw?** The concept is valid, but the `type: negative` syntax issue may prevent execution.

---

### 2.22 `openclaw-secrets-resolve.yaml` -- Secrets Plaintext Extraction

**Severity**: critical
**Verdict**: STRONGEST WebSocket template -- specific and meaningful

```yaml
inputs:
  - data: '{"jsonrpc":"2.0","id":1,"method":"secrets.resolve","params":{"commandName":"system.run","targetIds":["env"]}}'
matchers:
  - type: word
    words: ["assignments", "value", "path"]
    condition: and
```

**Problems**:
- This is the best WebSocket template in the set. It tests a specific, dangerous API method (`secrets.resolve`) that could return plaintext secrets.
- Using `condition: and` (requiring ALL words) is much stronger than the `or` pattern used elsewhere.
- The response words (`assignments`, `value`, `path`) are specific to the secrets resolution response format.
- The method name and params structure suggest actual knowledge of the OpenClaw API.
- Weakness: no `type: negative` for error responses (but that is actually fine here since the `and` condition is strong enough).

**Would it work against real OpenClaw?** Yes, with high confidence. This is the best template in the collection.

---

### 2.23 `openclaw-responses-api.yaml` -- Responses API Endpoint

**Severity**: medium
**Verdict**: WEAK -- overly broad status/word matching

```yaml
matchers:
  - type: status
    status: [200, 400, 401]
  - type: word
    part: body
    words: ["error", "model", "output", "response"]
    condition: or
```

**Problems**:
- Accepts 200, 400, or 401 status codes. Three out of the most common HTTP statuses.
- Body words `error`, `model`, `output`, `response` are ubiquitous in any API.
- Combined, this matches almost any API endpoint that returns JSON.
- The `/v1/responses` path is the OpenAI Responses API format, which is used by many LLM API gateways, not just OpenClaw.

**Would it work against real OpenClaw?** Yes, but also on any OpenAI-compatible API proxy. Very low specificity.

---

## 3. Critical Findings Summary

### 3.1 Syntax / Structural Issues

| Issue | Affected Templates | Severity |
|-------|-------------------|----------|
| `type: negative` is not valid Nuclei matcher syntax; should be `negative: true` on `type: word` | `openclaw-full-rce.yaml`, `openclaw-rogue-node.yaml` | **BLOCKING** -- templates will fail to parse |
| `{{BaseURL}}:9222` URL construction likely broken (BaseURL already contains scheme+host+port) | `openclaw-browser-cdp.yaml` | **BLOCKING** -- invalid URL generation |
| Multi-request blocks in HTTP/WS do not share state -- "chain" templates are actually independent tests | `openclaw-full-rce.yaml`, `openclaw-transcript-theft.yaml` | **DESIGN** -- claimed functionality is misleading |
| Missing `matchers-condition` defaults to OR in some Nuclei versions | `openclaw-canvas-exposed.yaml`, `openclaw-openai-compat.yaml` | **MINOR** -- behavior may vary across Nuclei versions |

### 3.2 Duplicate / Overlapping Templates

| Group | Templates | Overlap |
|-------|-----------|---------|
| **Auth bypass on /v1/chat/completions** | `openclaw-no-auth.yaml`, `openclaw-default-token.yaml`, `openclaw-weak-tokens.yaml` | All three test the same endpoint. `weak-tokens` subsumes `default-token` (first payload is the same). `no-auth` and `default-token` differ only in the Authorization header. |
| **Sessions enumeration** | `openclaw-sessions-exposed.yaml`, `openclaw-transcript-theft.yaml` (request 1) | Identical endpoint, identical method, overlapping matchers. |
| **API detection** | `openclaw-detect.yaml`, `openclaw-openai-compat.yaml` | Both are info-severity detection templates with generic matchers. |

### 3.3 Templates by Effective Specificity

**OpenClaw-Specific (would only trigger on OpenClaw)**:
1. `openclaw-agent-files.yaml` -- matches CLAUDE.md/AGENTS.md filenames
2. `openclaw-exec-approvals.yaml` -- matches `allowAll` policy keyword
3. `openclaw-sessions-exposed.yaml` -- matches `sessionId`/`agentId`
4. `openclaw-secrets-resolve.yaml` -- matches `secrets.resolve` response format
5. `openclaw-rogue-node.yaml` -- matches `pairingCode`/`pairingId` (if syntax fixed)
6. `openclaw-transcript-theft.yaml` -- matches session transcript fields

**Semi-Specific (OpenClaw paths but generic matchers)**:
7. `openclaw-canvas-exposed.yaml` -- OpenClaw path, status-only matcher
8. `openclaw-full-rce.yaml` -- OpenClaw WS methods, broken chain
9. `openclaw-weak-tokens.yaml` -- good fuzzing, generic endpoint
10. `openclaw-default-token.yaml` -- specific token, ambiguous matcher
11. `openclaw-hooks-no-auth.yaml` -- plausible paths, negative matching

**Generic (not OpenClaw-specific, would fire on many targets)**:
12. `openclaw-detect.yaml` -- JSON health check
13. `openclaw-openai-compat.yaml` -- any-status matcher
14. `openclaw-no-auth.yaml` -- status-only matcher on common endpoint
15. `openclaw-cors-misconfig.yaml` -- standard CORS test
16. `openclaw-plugin-traversal.yaml` -- standard LFI test
17. `openclaw-browser-cdp.yaml` -- standard CDP check, broken URL
18. `openclaw-ws-no-auth.yaml` -- generic JSON-RPC check
19. `openclaw-responses-api.yaml` -- any-API matcher
20. `openclaw-oauth-redirect.yaml` -- standard OAuth redirect test
21. `openclaw-slack-no-signature.yaml` -- standard webhook signature test
22. `openclaw-discord-interactions.yaml` -- generic word matcher
23. `openclaw-mattermost-inject.yaml` -- generic word matcher

---

## 4. Quantitative Assessment

| Metric | Count | Percentage |
|--------|-------|------------|
| Total templates | 23 | 100% |
| Would parse successfully in Nuclei | 20 | 87% |
| **Would fail to parse** (invalid `type: negative`, broken URL) | **3** | **13%** |
| OpenClaw-specific detection (meaningful matchers) | 6 | 26% |
| Semi-specific (right paths, weak matchers) | 5 | 22% |
| Generic rebranded checks | 12 | 52% |
| Status-code-only matchers (essentially useless) | 3 | 13% |
| Contains duplicate/overlapping logic | 5 | 22% |
| Effective unique templates after dedup | ~18 | -- |
| Would actually detect claimed vulnerability | ~8 | 35% |

---

## 5. Quality Comparison to Nuclei Community Templates

### What community templates typically have that these lack:

1. **`remediation` field** -- Community templates include remediation guidance. None of these 23 have it.

2. **`reference` field** -- Only 1 of 23 (`openclaw-no-auth.yaml`) includes a reference URL, and it points to a non-existent GitHub repo (`https://github.com/openclaw/openclaw/blob/main/SECURITY.md`). Community templates typically link to CVEs, blog posts, or vendor advisories.

3. **`classification` field** -- Community templates include CVSS scores, CWE IDs, and CVE numbers where applicable. None of these 23 have any classification metadata.

4. **`metadata` field** -- Only `openclaw-detect.yaml` has metadata (Shodan/FOFA queries). The rest have none. Community templates typically include `max-request`, `verified`, and `product` metadata.

5. **Multi-step request chaining** -- Community templates use proper Nuclei `req-condition` and pipeline features for multi-step attacks. The "chain" templates here (`openclaw-full-rce.yaml`, `openclaw-transcript-theft.yaml`) use independent request blocks that do not share state.

6. **Regex matchers** -- None of the 23 templates use regex matchers. Community templates frequently use regex for precise pattern matching (e.g., `"version"\s*:\s*"[0-9]+"` instead of matching the word `"version"`).

7. **DSL matchers** -- Zero use of Nuclei's DSL matcher language. Community templates use DSL for conditional logic (e.g., `status_code == 200 && contains(body, "pattern")`).

8. **`stop-at-first-match`** -- Only `openclaw-weak-tokens.yaml` uses this. Other multi-path templates could benefit from it.

### Quality Rating

| Aspect | Rating | Notes |
|--------|--------|-------|
| Template structure / YAML validity | 4/10 | 3 templates have likely-invalid syntax |
| Matcher specificity | 3/10 | Most matchers are too generic |
| False positive resistance | 2/10 | ~52% of templates would fire on non-OpenClaw targets |
| Attack chain accuracy | 2/10 | Chained templates do not actually chain |
| Community template standard compliance | 2/10 | Missing remediation, classification, metadata |
| Coverage of claimed attack surface | 5/10 | Good breadth of endpoints, poor depth |
| Documentation / descriptions | 6/10 | Descriptions are clear and informative |
| Overall quality | **3/10** | Below community template standards |

---

## 6. Verdict

**The 23-template claim is numerically accurate.** There are indeed 23 `.yaml` files in the `nuclei-templates/` directory.

**However, the quality and effectiveness is significantly overstated.** The actual breakdown:

- **~6 templates** (26%) are genuinely OpenClaw-specific and would provide meaningful detection results against a real instance. These target the `/__openclaw__/a2ui/api/` endpoints and the WebSocket JSON-RPC API with specific response field matching.

- **~5 templates** (22%) target plausible OpenClaw paths but have matchers so generic that they would produce false positives on non-OpenClaw targets.

- **~12 templates** (52%) are standard web security checks (CORS reflection, LFI, CDP exposure, status-code-only checks) that have been renamed with "openclaw-" prefixes. These are not OpenClaw-specific and could be replaced by existing community Nuclei templates.

- **3 templates** will likely fail at Nuclei parse time due to invalid syntax (`type: negative` instead of `negative: true` on word matchers, and broken URL construction in the CDP template).

- **2 "chain" templates** claim multi-step attack flows but actually execute independent requests with no state sharing, making the claimed attack chain misleading.

**In production use**, running these 23 templates against a real OpenClaw instance would produce:
- Genuine findings from ~6 templates
- Ambiguous results from ~5 templates
- False positives or parse errors from ~12 templates

**Recommendation**: The template set needs significant rework to meet production quality standards. The 6 genuinely specific templates (agent-files, exec-approvals, sessions-exposed, secrets-resolve, rogue-node, transcript-theft) form a solid foundation that should be expanded with proper matchers, classification metadata, and remediation guidance. The 12 generic templates should either be removed or substantially rewritten with OpenClaw-specific matchers.

---

*Report generated by Claude Opus 4.6 code-reviewer agent*
