<h1 align="center">🦞 CatchClaw v6.0.0 (Go)</h1>

<p align="center">
  <b>Multi-platform AI Agent security assessment tool — 101 exploit modules | 27 platforms | DAG attack chains</b><br>
  <sub>Complete Go rewrite of CatchClaw Rust v5.3.0 | ATT&CK mapping | Concurrent execution | 2025-2026 CVE coverage</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-6.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Modules-101-FF6B6B?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/Platforms-27-purple?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/DAG_Chains-101-4CAF50?style=flat-square" alt="Chains">
</p>

---

## What is CatchClaw?

**CatchClaw** is a comprehensive AI Agent and LLM platform security assessment tool. It detects vulnerabilities across AI infrastructure — from exposed Ollama instances to multi-tenant Dify deployments — using 87 orchestrated exploit modules organized into DAG attack chains mapped to the MITRE ATT&CK framework.

### v6.0.0 Go Rewrite Highlights

| Improvement | Details |
|---|---|
| **Language** | Complete rewrite from Rust to Go — single static binary, no runtime dependencies |
| **Performance** | Goroutine-based concurrency, connection pooling, optimized HTTP client |
| **New Platforms** | Langflow, LiteLLM, Ollama, vLLM probes added (15 total platforms) |
| **New CVEs** | DifyTap (CVE-2026-41947-50), Langflow RCEs, LiteLLM MCP injection, LobeChat RAG |
| **2026 CVEs** | LangChain deserialization RCE (CVE-2025-68664), CrewAI flaws (CVE-2026-2275/2285/2286/2287), LangGraph pickle RCE (CVE-2026-27794), Spring AI SSRF (CVE-2026-45609), WordPress AI Engine RCE (CVE-2026-8719) |
| **YAML Payloads** | Integrated with root `payloads/*.yaml` files for dynamic payload loading |
| **Module System** | Interface-based (`Module` interface), auto-registration via `init()` |
| **DAG Engine** | Kahn's topological sort, level-parallel goroutine execution, semaphore control |
| **Extensibility** | Add new modules by implementing one interface — auto-registered |
| **Nuclei Support** | Run Nuclei templates directly via `catchclaw nuclei` command |

---

## Installation

### Build from Source

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/go

# Build
go build -o catchclaw .

# Or install directly
go install github.com/Coff0xc/catchclaw/go@latest
```

### Cross-Compile

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o catchclaw-linux .

# macOS
GOOS=darwin GOARCH=amd64 go build -o catchclaw-macos .

# Windows
GOOS=windows GOARCH=amd64 go build -o catchclaw.exe .
```

### Requirements

- Go 1.22+
- No external runtime dependencies (single binary)

---

## Quick Start

```bash
# List all 101 exploit modules
catchclaw list

# Scan a target (auto-detect platform)
catchclaw scan -t 192.168.1.100:8080

# Scan with HTML report
catchclaw scan -t 192.168.1.100:8080 -o report.html --format html

# Scan CIDR range
catchclaw scan --targets "192.168.1.0/24:8080" -o results.json

# Scan from file
catchclaw scan -f targets.txt -o results.json

# Dry-run (preview attack plan)
catchclaw scan -t 192.168.1.100:8080 --dry-run

# Run single exploit chain node
catchclaw exploit -t 192.168.1.100:8080 --chain-id 6

# Port scan + platform fingerprinting
catchclaw discover -t 192.168.1.100

# Discover specific ports
catchclaw discover -t 192.168.1.100 --ports 3000,8080,11434

# List Nuclei templates
catchclaw nuclei --list

# Run Nuclei templates
catchclaw nuclei -t http://192.168.1.100:8080
```

---

## Supported Platforms

| Platform | Fingerprinting | CVE Coverage | Probe Module |
|------|------|---------|---------|
| **OpenClaw / Open-WebUI** | Auto | 72 dedicated modules | Built-in |
| **Dify** | Auto | CVE-2025-56157, CVE-2025-56520, CVE-2026-105761/62, DifyTap | `dify_probe`, `dify_tap_probe` |
| **FastGPT** | Auto | CVE-2025-27600, CVE-2025-52552 | `fastgpt_probe` |
| **LobeChat** | Auto | CVE-2026-23733, CVE-2026-53489 | `lobechat_probe` |
| **LibreChat** | Auto | CVE-2025-69222, CVE-2025-69220 | `librechat_probe` |
| **NextChat** | Auto | CVE-2023-49785 | `nextchat_probe` |
| **AnythingLLM** | Auto | CVE-2024-13059, CVE-2024-0455 | `anythingllm_probe` |
| **Flowise** | Auto | CVE-2025-26319, CVE-2026-41264 | `flowise_probe` |
| **RagFlow** | Auto | CVE-2024-12433, CVE-2024-12450 | `ragflow_probe` |
| **Langflow** | Auto | CVE-2026-21445/33017/55255/105740/93680/110186 | `langflow_probe` |
| **LiteLLM** | Auto | CVE-2026-42271, CVE-2026-49468, CVE-2026-42208 | `litellm_probe` |
| **Ollama** | Auto | CVE-2024-37032 (Probllama), Exposed API | `ollama_probe`, `ollama_probllama` |
| **vLLM** | Auto | Exposed API detection | `vllm_probe` |
| **Ray Dashboard** | Auto | CVE-2023-6019/6020/6021 (ShadowRay) | `ray_probe` |
| **MLflow** | Auto | CVE-2024-1483, CVE-2024-27132 | `mlflow_probe` |
| **Gradio** | Auto | CVE-2024-1561, CVE-2024-47084 | `gradio_probe` |
| **ComfyUI** | Auto | CVE-2024-10099, CVE-2025-6730 | `comfyui_probe` |
| **DB-GPT** | Auto | CVE-2024-6502, CVE-2024-5451 | `dbgpt_probe` |
| **ChromaDB** | Auto | Unauthenticated vector DB exposure | `chromadb_probe` |
| **Qdrant** | Auto | CVE-2024-2221, Unauth API | `qdrant_probe` |
| **Weaviate** | Auto | Unauthenticated schema exposure | `weaviate_probe` |
| **Milvus** | Auto | Unauthenticated vector DB API | `milvus_probe` |
| **LocalAI** | Auto | CVE-2024-6983 (Gallery RCE) | `localai_probe` |
| **Xinference** | Auto | CVE-2024-45857 (Unauth Model Launch) | `xinference_probe` |
| **Jupyter** | Auto | Unauthenticated kernel RCE | `jupyter_probe` |

---

## 87 Exploit Modules

### Recon (19 modules)

| Module | Category | Description |
|------|------|------|
| cors_bypass | Config | Origin reflection → cross-origin WS/API access |
| ws_hijack | Transport | Cross-origin WebSocket upgrade + token replay |
| auth_mode_abuse | Auth | Authentication mode detection and abuse |
| log_disclosure | Disclosure | Credential/sensitive data leakage via logs.query |
| hidden_content | Disclosure | Hidden content discovery (.env, .git, etc.) |
| origin_wildcard | Config | Origin wildcard configuration detection |
| gateway_hijack | Transport | gatewayURL WebSocket hijacking (CVE-2026-25253) |
| localhost_trust | Auth | Authentication bypass via implicit localhost trust |
| mdns_leak | DataLeak | mDNS/HTTP configuration parameter leakage |
| dify_probe | Recon | Dify security probe (CVE-2025-56157/56520) |
| dify_tap_probe | Recon | DifyTap cross-tenant exposure (CVE-2026-41947-50) |
| fastgpt_probe | Recon | FastGPT security probe (CVE-2025-27600) |
| lobechat_probe | Recon | LobeChat security probe (CVE-2026-23733/53489) |
| librechat_probe | Recon | LibreChat security probe (CVE-2025-69222/69220) |
| nextchat_probe | Recon | NextChat security probe (CVE-2023-49785) |
| anythingllm_probe | Recon | AnythingLLM security probe (CVE-2024-13059/0455) |
| flowise_probe | Recon | Flowise security probe (CVE-2025-26319/41264) |
| ragflow_probe | Recon | RagFlow security probe (CVE-2024-12433/12450) |
| langflow_probe | Recon | Langflow security probe (CVE-2026-21445/33017/55255/105740) |
| litellm_probe | Recon | LiteLLM security probe (CVE-2026-42271/49468) |
| ollama_probe | Recon | Ollama exposed API detection |
| vllm_probe | Recon | vLLM exposed API detection |

### Initial Access (24 modules)

| Module | Category | Description |
|------|------|------|
| ssrf | SSRF | SSRF via pipelines (AWS/GCP/Azure metadata) |
| eval_inject | Injection | eval/exec code execution |
| prompt_inject | Injection | System prompt extraction + instruction override |
| mcp_inject | Injection | MCP plugin injection |
| pairing_brute | Auth | 6-digit DM pairing code brute force |
| oauth_abuse | Auth | Slack OAuth redirect hijacking |
| responses_exploit | API | /v1/responses authentication bypass + tool injection |
| ws_fuzz | Fuzz | Malformed JSON-RPC + method injection |
| acp_bypass | Auth | ACP access control bypass |
| csrf_no_origin | Config | CSRF without Origin validation |
| silent_pair_abuse | Auth | Silent pairing abuse |
| ratelimit_scope_bypass | Config | Rate-limit scope bypass |
| ipv6_ssrf_bypass | SSRF | IPv6 loopback SSRF bypass |
| msg_platform_spoof | Auth | Message platform spoofing (Slack/Discord/Mattermost) |
| skill_supply_chain | DataLeak | Malicious Skill supply-chain attack (AMOS) |
| guest_mode_abuse | Config | Guest Mode exposes dangerous API endpoints |
| channel_inject | Injection | Unsigned command injection for Mattermost/Slack/Discord |
| ws_auth_brute | Auth | WebSocket authentication brute force (CVE-2026-32025) |
| ssrf_rebind | SSRF | DNS Rebind SSRF |
| ssrf_proxy_bypass | SSRF | Proxy bypass SSRF |
| browser_request | SSRF | Browser request internal dispatch |
| unicode_bypass | Injection | Unicode homoglyph bypass |
| obfuscation_bypass | Injection | Obfuscation/Unicode bypass |
| skill_scanner_bypass | Config | Skill security scanner bypass |
| langchain_deser_rce | RCE | LangChain deserialization RCE (CVE-2025-68664) |
| springai_ssrf | SSRF | Spring AI SSRF (CVE-2026-45609) |

### Credential Access (12 modules)

| Module | Category | Description |
|------|------|------|
| apikey_steal | Credential | Provider API key extraction |
| oauth_token_theft | Credential | OAuth token theft |
| secret_extract | Credential | Plaintext theft via secrets.list + secrets.get |
| secrets_resolve | Credential | secrets.resolve internal injection API |
| talk_secrets | Credential | Key leakage via talk.config(includeSecrets) |
| session_hijack | Session | IDOR in sessions.preview + cross-session injection |
| auth_disable_leak | Auth | Authentication-disable leakage |
| exec_socket_leak | DataLeak | Execution socket leak |
| secret_exec_abuse | RCE | Secret execution abuse |
| redact_bypass | DataLeak | Redaction bypass |

### Execution (16 modules)

| Module | Category | Description |
|------|------|------|
| rce | RCE | Command execution probe via system.run |
| hook_inject | RCE | Command execution via webhook endpoint injection |
| tools_invoke | RCE | Bypass the Chat-layer security via tools.invoke |
| keychain_cmd_inject | RCE | Keychain command injection |
| qmd_cmd_inject | RCE | QMD command injection |
| exec_race_toctou | RCE | Execution race condition (TOCTOU) |
| browser_upload_traversal | RCE | Browser upload path traversal |
| voice_ext_rce | RCE | Voice extension RCE (CVE-2026-28446) |
| env_inject | Injection | Environment variable injection (CVE-2026-32056) |
| safebins_bypass | RCE | SafeBins allowlist bypass (CVE-2026-28363) |
| agent_inject | Injection | Backdoor via agents.create/update |
| agent_file_inject | Injection | Persistent prompt backdoor via agents.files.set |
| bypass_soul | Injection | Soul protection bypass |
| marker_spoof | Injection | Marker/homoglyph spoofing |
| session_file_write | RCE | Arbitrary file write via sessions.patch |
| patch_escape | Traversal | Path traversal in apply_patch |
| link_template_inject | Injection | Link template injection |
| approval_hijack | Auth | Prefix ID matching + execution policy tampering |
| config_tamper | Config | config.set security configuration write |
| crewai_flaw | RCE | CrewAI multi-flaw RCE (CVE-2026-2275/2285/2286/2287) |
| langgraph_pickle_rce | RCE | LangGraph pickle deserialization RCE (CVE-2026-27794) |
| wp_ai_engine | RCE | WordPress AI Engine RCE (CVE-2026-8719) |

### Persistence (5 modules)

| Module | Category | Description |
|------|------|------|
| config_tamper | Config | Security configuration write |
| skill_poison | Injection | Skill poisoning |
| cron_bypass | Persistence | Cron blacklist bypass + persistence |
| webhook_verify | Config | Webhook verification bypass |
| flood_guard_reset | Config | Flood guard reset |

### Lateral Movement (1 module)

| Module | Category | Description |
|------|------|------|
| rogue_node | Injection | Self-approved node pairing → command interception |

### Exfiltration (8 modules)

| Module | Category | Description |
|------|------|------|
| session_hijack | DataLeak | IDOR in sessions.preview |
| transcript_theft | DataLeak | Session transcript theft |
| memory_data_leak | DataLeak | Memory data leakage |
| c2_exfil | Exfil | C2 data exfiltration |
| redact_bypass | DataLeak | Redaction bypass |
| obfuscation_bypass | Injection | Obfuscation bypass |
| skill_scanner_bypass | Config | Skill scanner bypass |
| secret_exec_abuse | RCE | Secret execution abuse |

---

## DAG Attack Chain Architecture

```
                    ┌─────────────────────┐
                    │   Level 0 (Recon)    │
                    │  19 parallel probes  │
                    └─────────┬───────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  Level 1 (Init) │ │  Level 1 (Cred) │ │  Level 1 (Init) │
│  SSRF/Eval/     │ │  APIKey/OAuth   │ │  Prompt/MCP/    │
│  Pairing/OAuth  │ │  Token Theft    │ │  Responses      │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ▼
               ┌─────────────────────────┐
               │   Level 2 (Execution)   │
               │  RCE/Hook/Tools/Agent   │
               │  Session Write          │
               └────────────┬────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼                           ▼
    ┌─────────────────┐         ┌─────────────────┐
    │ Level 3 (Persis)│         │ Level 3 (Priv)  │
    │ Agent/Cron/     │         │ Approval/Node   │
    │ Skill Poison    │         │ Config Tamper   │
    └────────┬────────┘         └────────┬────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
              ┌─────────────────────────┐
              │   Level 4 (Exfil)       │
              │  C2/Transcript/         │
              │  Memory Leak            │
              └─────────────────────────┘
```

**Execution:**
- Kahn topological sort → level-by-level parallel goroutine execution
- Semaphore (buffered channel) controls maximum concurrency
- `DependsOn` — predecessor nodes must complete
- `FallbackFor` — skip fallback if parent node has findings
- `Condition` — conditional execution based on earlier results
- Attack graph records each node's executed/skipped/fallback status

---

## Configuration

Create `catchclaw.yaml` in the working directory:

```yaml
scanner:
  timeout: 15
  concurrency: 20
  log_level: "info"
  aggressive: false

proxy:
  http: "http://127.0.0.1:8080"
  # socks5: "socks5://127.0.0.1:9050"

payload:
  file: "payloads.yaml"
  enable_mutation: true

graph:
  export_mermaid: true
  output_dir: "./reports"

profile:
  quick:
    scanner:
      timeout: 5
      concurrency: 30
  stealth:
    scanner:
      timeout: 30
      concurrency: 2
    proxy:
      socks5: "socks5://127.0.0.1:9050"
  full:
    scanner:
      timeout: 20
      concurrency: 15
      aggressive: true
```

Use with: `catchclaw scan -t target:port --config catchclaw.yaml --profile stealth`

---

## Extending CatchClaw

Add a new exploit module by implementing the `Module` interface:

```go
package modules

import (
    "github.com/Coff0xc/catchclaw/go/internal/config"
    "github.com/Coff0xc/catchclaw/go/internal/core"
    "github.com/Coff0xc/catchclaw/go/internal/exploit"
)

type MyModule struct{}

func (m MyModule) Meta() exploit.ModuleMeta {
    return exploit.ModuleMeta{
        ID:       "my_module",
        Name:     "My Module",
        Category: exploit.CatInjection,
        Phase:    exploit.PhaseInitAccess,
        CVE:      "CVE-2026-XXXXX",
    }
}

func (m MyModule) Run(target core.Target, cfg *config.Config) ([]core.Finding, core.Outcome) {
    ctx := exploit.NewContext(&target, cfg, nil)
    var findings []core.Finding

    // Your exploit logic here
    resp, err := ctx.Get(ctx.BaseURL + "/api/vulnerable-endpoint")
    if err != nil {
        return findings, core.OutcomeError
    }
    body, _, status := ctx.AnalyzeResponse(resp)

    if status == 200 && strings.Contains(body, "vulnerable") {
        findings = append(findings, core.NewFinding(
            ctx.Target.String(), "my_module", "Vulnerability Found",
            core.Critical, "Description of the vulnerability",
        ).WithEvidence(body).WithRemediation("How to fix"))
    }

    return findings, core.OutcomeClean
}
```

Register in `register.go` — done. The module is automatically:
- Listed in `catchclaw list`
- Added to the DAG with proper dependencies
- Executed in parallel with other modules

---

## CLI Reference

```
catchclaw scan -t TARGET [FLAGS]
  -t, --target <HOST:PORT>     Target address
      --targets <SPEC>         Multi: comma,CIDR,IP range
  -f, --targets-file <FILE>    Target file
      --token <TOKEN>          Auth token
      --timeout <SECS>         Timeout (default 10)
  -o, --output <FILE>          Output path
      --format <FMT>           json | html | markdown
      --concurrency <N>        Max concurrency
      --tls                    HTTPS/WSS
      --callback <URL>         SSRF callback
      --profile <NAME>         Config profile
      --severity-filter <SEV>  Filter results
      --dry-run                Preview only
      --config <FILE>          Config file
      --platform <PLATFORM>    Target platform

catchclaw exploit -t TARGET [--chain-id N]
catchclaw discover -t HOST [--ports P1,P2] [--timeout N]
catchclaw nuclei -t URL [--templates DIR] [--list]
catchclaw list
catchclaw config
catchclaw version
```

---

## Project Structure

```
go/
├── main.go                          # Entry point
├── go.mod
└── internal/
    ├── cli/cli.go                   # CLI commands and flags
    ├── config/config.go             # Config loading (YAML/TOML/JSON)
    ├── core/
    │   ├── types.go                 # Target, Finding, Severity, ScanResult
    │   └── dag.go                   # DAG engine, Kahn's sort, attack graph
    ├── exploit/
    │   ├── registry.go              # Module registry
    │   ├── context.go               # Exploit execution context
    │   └── modules/                 # 101 exploit modules
    │       ├── core.go              # SSRF, RCE, eval, prompt injection, etc.
    │       ├── auth.go              # CORS, WS hijack, OAuth, pairing, etc.
    │       ├── dataleak.go          # API key, secrets, sessions, etc.
    │       ├── injection.go         # Agent, channel, skill, cron, etc.
    │       ├── cve.go               # CVE-specific exploit modules
    │       ├── platform.go          # 14 platform probes
    │       └── register.go          # Auto-registration
    ├── platform/
    │   ├── platform.go              # Platform types, registry, endpoint kinds
    │   └── profiles.go              # 15 platform profile implementations
    ├── payload/
    │   ├── payload.go               # YAML payload registry
    │   └── mutate.go                # Payload mutation/obfuscation engine
    ├── nuclei/
    │   └── nuclei.go                # Nuclei template runner
    ├── scan/
    │   ├── scan.go                  # Scan orchestration, DAG builder
    │   └── discovery.go             # Port scan, service fingerprinting
    ├── report/
    │   └── report.go                # JSON/HTML/Markdown/Mermaid export
    └── utils/
        ├── http.go                  # HTTP client, false-positive filters
        └── ws.go                    # WebSocket client (coder/websocket)
```

---

## Performance

| Metric | Rust v5.3.0 | Go v6.0.0 |
|--------|-------------|-----------|
| Binary size | ~8 MB | ~6 MB |
| Memory (idle) | ~15 MB | ~8 MB |
| Concurrent connections | Tokio semaphore | Go channels |
| Startup time | ~50ms | ~10ms |
| Module count | 78 | 87 |
| Platform count | 9 | 15 |
| CVE coverage | 2025-2026 | 2025-2026 + 5 new CVEs |

---

## Disclaimer

This tool is intended for **authorized security testing** only. Test only systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal.

## Author

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## License

Non-commercial use only. See [LICENSE](../LICENSE) for details.