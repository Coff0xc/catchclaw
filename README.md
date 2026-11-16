<h1 align="center">🦞 CatchClaw v5.3.0</h1>

<p align="center">
  <b>Multi-platform AI Agent security assessment tool — supports 9 major platforms including OpenClaw / Dify / FastGPT / LobeChat</b><br>
  <sub>78 DAG attack chains | 78 Exploit modules | 9 platforms supported | ATT&CK stage mapping | Async Tokio engine | Attack graph visualization</sub>
</p>

<p align="center">
  <a href="README.md"><b>English</b></a> ·
  <a href="README_JA.md">Japanese</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/catchclaw/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/catchclaw?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/catchclaw/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/catchclaw?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/catchclaw/issues"><img src="https://img.shields.io/github/issues/Coff0xc/catchclaw?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/catchclaw/commits/master"><img src="https://img.shields.io/github/last-commit/Coff0xc/catchclaw?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-5.3.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Rust-Edition_2024-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/DAG_Chains-78-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Async-Tokio-4CAF50?style=flat-square" alt="Tokio">
  <img src="https://img.shields.io/badge/Exploits-78_Modules-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/Platforms-9-purple?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/License-Non--Commercial--v2.0-green?style=flat-square" alt="License">
</p>

---

> **⚠️ COMMERCIAL USE STRICTLY PROHIBITED**
>
> This project is licensed under the **CatchClaw Strict Non-Commercial License v2.0**.
>
> **Any form of commercial use is strictly prohibited without written authorization from the copyright holder (Coff0xc).** Violators will be held legally liable.
>
> Prohibited activities include, but are not limited to:
> - Selling, sublicensing, or renting this software or its derivative works
> - Using this software for SaaS, penetration testing services, consulting, or any paid service
> - Integrating it into commercial products, platforms, or tools
> - Using it to train commercial AI/ML models
> - Renaming, reskinning, or repackaging and redistributing it
> - Any activity that directly or indirectly generates revenue
>
> **The copyright holder reserves the right to pursue claims indefinitely, including recovery of all profits, legal fees, and punitive damages.**
>
> See [LICENSE](LICENSE) for details.

---

## Highlights

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CatchClaw v5.3.0                                │
├────────────────────────────────────────────────────────────────────────────┤
│  ● 78 DAG attack chains ● 78 Exploit modules ● Async Tokio engine        │
│  ● ATT&CK 9-stage mapping ● Mermaid graph export ● JSON/HTML/MD reports  │
│  ● Kahn topological sort ● Semaphore control ● Conditional/fallback      │
│  ● Multi-target scan (CIDR) ● Port scan/service discovery ● 200+ Payloads│
│  ● 9 platforms ● Multi-platform fingerprinting ● --platform auto-detect  │
├────────────────────────────────────────────────────────────────────────────┤
│  Attack surface: WS API | HTTP REST | OAuth | Webhook | Node | Multi-Platform │
│  Coverage: SSRF | RCE | key theft | hijacking | privesc | persistence | leaks │
│  New: C2 exfil, Skill poison, Agent inject, MCP inject, OAuth theft, DNS Rebind │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

- [Project Overview](#project-overview)
- [Core Features](#core-features)
- [Supported Platforms](#supported-platforms)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [78 Exploit Modules](#78-exploit-modules)
- [DAG Attack Chain Architecture](#dag-attack-chain-architecture)
- [Nuclei Templates](#nuclei-templates)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)

---

## Project Overview

**CatchClaw** is a Rust-based multi-platform AI Agent security assessment tool supporting 9 major AI platforms, including [OpenClaw](https://github.com/anthropics/open-claw) / Open-WebUI, Dify, FastGPT, and LobeChat. With 78 DAG attack chains and 78 Exploit modules, it covers the full ATT&CK kill chain, from initial reconnaissance to data exfiltration.

Built on the Tokio async runtime, the DAG engine executes level by level in parallel using Kahn's topological sort, with a Semaphore controlling concurrency, and supports conditional execution and fallback nodes. Attack graphs can be exported as Mermaid flowcharts.

### Why Choose CatchClaw?

| Scenario | Manual Testing | CatchClaw |
|------|---------|-----------|
| **Vulnerability validation** | Hand-written PoCs, one by one | 78 chains orchestrated and validated automatically |
| **Attack surface coverage** | Based on experience | Full coverage of WS + HTTP + OAuth + Webhook + Node |
| **Dependency chain discovery** | Hard to trace | DAG automatically discovers vulnerability dependency paths |
| **Result visualization** | Organized by hand | Mermaid attack graphs + JSON/HTML/Markdown reports |
| **CI/CD integration** | None | 24 Nuclei templates, plug and play |
| **Multi-target scanning** | Tested manually, one by one | Batch scanning of CIDR blocks, IP ranges, and target files |
| **Service discovery** | Requires nmap | Built-in port scanning + multi-platform fingerprinting |
| **Multi-platform coverage** | Each platform researched separately | Automatic detection across 9 platforms: OpenClaw/Dify/FastGPT/NextChat/AnythingLLM/Flowise/RagFlow/LibreChat/LobeChat |

---

## Core Features

<table>
<tr>
<td width="50%">

### Attack Engine

- **78 Exploit modules** — covering 10 major categories, auto-registered by the `inventory` macro
- **78 DAG attack chains** — auto-orchestrated across 9 ATT&CK stages
- **Kahn topological sort** — level-by-level parallel execution with automatic dependency resolution
- **Conditional/fallback nodes** — execution paths decided dynamically from earlier results
- **Attack graph visualization** — Mermaid export, marking hit/skipped/fallback status

</td>
<td width="50%">

### Protocol Support

- **WebSocket Gateway** — challenge handshake detection, JSON-RPC calls
- **HTTP REST** — redirects disabled to prevent OAuth 302 false positives
- **False-positive elimination** — challenge page / SPA fallback / LLM refusal detection
- **TLS support** — rustls backend, `--tls` enables HTTPS/WSS
- **Multi-format reports** — JSON + HTML (dark theme) + Markdown

</td>
</tr>
<tr>
<td width="50%">

### Scanning Enhancements

- **Multi-target scanning** — CIDR (/24), IP ranges, comma-separated lists, target files
- **Port scanning** — TCP connect scan + custom port ranges
- **Service discovery** — multi-platform fingerprinting (automatic detection of 9 major AI platforms)
- **200+ Payloads** — external YAML libraries for SSRF/injection/prompt/auth/XSS
- **Scan configuration** — TOML config files + Profile presets + proxy support

</td>
<td width="50%">

### CLI Experience

- **`--profile`** — Use a preset scan configuration (quick/stealth/full)
- **`--severity-filter`** — Filter results by severity
- **`--format`** — Choose the output format: json/html/markdown
- **`--dry-run`** — Preview the DAG execution plan without actually scanning
- **`--targets-file`** — Batch target file input
- **`--platform`** — Specify the target platform type (auto-detect / manual)

</td>
</tr>
</table>

---

## Supported Platforms

| Platform | Version | Fingerprinting | CVE Coverage | Probe Module |
|------|------|---------|---------|---------|
| **OpenClaw / Open-WebUI** | — | Auto | 72 dedicated modules | Built-in |
| **Dify** | v1.5+ | Auto | CVE-2025-56157, CVE-2025-55182 | `dify_probe` |
| **FastGPT** | v4.9+ | Auto | CVE-2025-27600, CVE-2025-52552 | `fastgpt_probe` |
| **NextChat** | v2.12+ | Auto | CVE-2023-49785 | `nextchat_probe` |
| **AnythingLLM** | v1.3+ | Auto | CVE-2024-13059, CVE-2024-0455 | `anythingllm_probe` |
| **Flowise** | v1.6+ | Auto | CVE-2025-26319, CVE-2025-58434 | `flowise_probe` |
| **RagFlow** | v0.14+ | Auto | CVE-2024-12433, CVE-2024-12450 | `ragflow_probe` |
| **LibreChat** | — | Auto | CVE-2025-69222, CVE-2025-69220 | `librechat_probe` |
| **LobeChat** | — | Auto | CVE-2026-23733 | `lobechat_probe` |

---

## Installation

### Build from Source

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Debug build
cargo build

# Release build (optimized, with symbol table stripped)
cargo build --release

# The binary is at target/release/catchclaw
```

### System Requirements

- Rust Edition 2024 (rustc 1.85+)
- Windows / Linux / macOS supported

---

## Quick Start

```bash
# List all registered modules
catchclaw list

# Auto-detect the platform type
catchclaw scan -t TARGET_IP:PORT

# Specify the platform type
catchclaw scan -t TARGET_IP:PORT --platform dify

# Scan and output a JSON report
catchclaw scan -t TARGET_IP:PORT -o report.json

# Output an HTML report
catchclaw scan -t TARGET_IP:PORT -o report.html --format html

# Multi-target scan (CIDR)
catchclaw scan --targets "192.168.1.0/24:8080"

# Batch scan from a file
catchclaw scan -f targets.txt -o results.json

# Use a Profile preset
catchclaw scan -t TARGET_IP:PORT --profile stealth

# Show only critical/high-severity results
catchclaw scan -t TARGET_IP:PORT --severity-filter critical,high

# Preview the execution plan
catchclaw scan -t TARGET_IP:PORT --dry-run

# Scan with a token
catchclaw scan -t TARGET_IP:PORT --token "your-gateway-token"

# Run the full attack chain
catchclaw exploit -t TARGET_IP:PORT --token xxx

# Run a single attack chain
catchclaw exploit -t TARGET_IP:PORT --chain-id 30
```

---

## CLI Usage

```
CatchClaw v5.3.0 — Multi-platform AI Agent security assessment tool

Usage: catchclaw <COMMAND>

Commands:
  scan      Full security scan (build DAG → execute → summarize)
  exploit   Run attack chains (full DAG or a single node)
  list      List all registered Exploit modules
  config    Show the current configuration

Scan Flags:
  -t, --target <HOST:PORT>     Target address (single target)
      --targets <SPEC>         Multiple targets: comma-separated, CIDR, or IP range
  -f, --targets-file <FILE>    Target file (one host:port per line)
      --token <TOKEN>          Gateway Token (or CATCHCLAW_TOKEN environment variable)
      --timeout <SECS>         Request timeout in seconds (default 10)
  -o, --output <FILE>          Report output path
      --format <FMT>           Output format: json | html | markdown (default json)
      --concurrency <N>        Maximum concurrency (default 10)
      --tls                    Use HTTPS/WSS
      --callback <URL>         SSRF callback URL
      --profile <NAME>         Use a Profile preset from the config file
      --severity-filter <SEV>  Filter by severity: critical,high,medium,low,info
      --dry-run                Preview the DAG execution plan
      --config <FILE>          Config file path (TOML/YAML/JSON)
      --platform <PLATFORM>    Specify the target platform type (auto|openclaw|dify|fastgpt|nextchat|anythingllm|flowise|ragflow|librechat|lobechat)

Exploit Flags:
  -t, --target <HOST:PORT>     Target address
      --token <TOKEN>          Gateway Token
      --chain-id <ID>          Run a single chain node ID
      --concurrency <N>        Maximum concurrency (default 10)
      --tls                    Use HTTPS/WSS
```

---

## 78 Exploit Modules

Grouped by ATT&CK stage and attack category:

### Recon

| Module | Category | Description |
|------|------|------|
| cors_bypass | Config | Origin reflection → cross-origin WS/API access |
| ws_hijack | Transport | Cross-origin WebSocket upgrade + token replay |
| auth_mode_abuse | Auth | Authentication mode detection and abuse |
| log_disclosure | DataLeak | Credential/sensitive data leakage via logs.query |
| hidden_content | DataLeak | Hidden content discovery |
| origin_wildcard | Config | Origin wildcard configuration detection |
| librechat_probe | Recon | LibreChat security probe (CVE-2025-69222/69220/54868) |
| lobechat_probe | Recon | LobeChat security probe (CVE-2026-23733 XSS) |
| dify_probe | Recon | Dify security probe (CVE-2025-56157 default credentials, SSRF) |
| fastgpt_probe | Recon | FastGPT security probe (CVE-2025-27600 SSRF, XSS) |
| nextchat_probe | Recon | NextChat security probe (CVE-2023-49785 SSRF) |
| anythingllm_probe | Recon | AnythingLLM security probe (CVE-2024-0455 SSRF) |
| flowise_probe | Recon | Flowise security probe (CVE-2025-26319 file upload) |
| ragflow_probe | Recon | RagFlow security probe (CVE-2024-12433 RCE) |

### Initial Access

| Module | Category | Description |
|------|------|------|
| ssrf | SSRF | browser.request/navigate → cloud metadata (AWS/GCP/Azure) |
| eval_inject | Injection | eval/exec code execution |
| prompt_inject | Injection | System prompt extraction + instruction override |
| mcp_inject | Injection | MCP plugin injection |
| pairing_brute | Auth | 6-digit DM pairing code brute force |
| oauth_abuse | Auth | Slack OAuth redirect hijacking |
| responses_exploit | API | /v1/responses authentication bypass + tool injection |
| ws_fuzz | Fuzz | Malformed JSON-RPC + method injection |
| acp_bypass | Auth | ACP access control bypass |
| ssrf_rebind | SSRF | DNS Rebind SSRF |
| ssrf_proxy_bypass | SSRF | Proxy bypass SSRF |
| browser_request | SSRF | Browser request internal dispatch |
| csrf_no_origin | Config | CSRF without Origin validation |

### Credential Access

| Module | Category | Description |
|------|------|------|
| apikey_steal | Credential | Provider API key extraction |
| oauth_token_theft | Credential | OAuth token theft |
| secret_extract | Credential | Plaintext theft via secrets.list + secrets.get |
| secrets_resolve | Credential | secrets.resolve internal injection API |
| talk_secrets | Credential | Key leakage via talk.config(includeSecrets) |

### Execution

| Module | Category | Description |
|------|------|------|
| rce | RCE | Command execution probe via system.run |
| hook_inject | RCE | Command execution via webhook endpoint injection |
| tools_invoke | RCE | Bypass the Chat-layer security via tools.invoke |
| keychain_cmd_inject | RCE | Keychain command injection |
| qmd_cmd_inject | RCE | QMD command injection |
| exec_race_toctou | RCE | Execution race condition (TOCTOU) |
| exec_socket_leak | RCE | Execution socket leak |

### Persistence

| Module | Category | Description |
|------|------|------|
| agent_inject | Injection | Backdoor via agents.create/update + system prompt leakage |
| agent_file_inject | Injection | Persistent prompt backdoor via agents.files.set |
| channel_inject | Injection | Unsigned command injection for Mattermost/Slack/Discord |
| skill_poison | Injection | Skill poisoning |
| cron_bypass | Persistence | Cron blacklist bypass + persistence |
| session_file_write | RCE | Arbitrary file write via sessions.patch |
| patch_escape | RCE | Path traversal in apply_patch → arbitrary file write |
| link_template_inject | Injection | Link template injection |

### Privilege Escalation

| Module | Category | Description |
|------|------|------|
| approval_hijack | Auth | Prefix ID matching + execution policy tampering |
| config_tamper | Config | config.set security configuration write |
| rogue_node | RCE | Self-approved node pairing → command interception |
| silent_pair_abuse | Auth | Silent pairing abuse |
| auth_disable_leak | Auth | Authentication-disable leakage |

### Lateral Movement / Exfiltration

| Module | Category | Description |
|------|------|------|
| session_hijack | DataLeak | IDOR in sessions.preview + cross-session injection |
| transcript_theft | DataLeak | Session transcript theft |
| memory_data_leak | DataLeak | Memory data leakage |
| c2_exfil | DataLeak | C2 data exfiltration |
| browser_upload_traversal | RCE | Browser upload path traversal |
| secret_exec_abuse | RCE | Secret execution abuse |
| bypass_soul | Injection | Soul bypass |
| marker_spoof | Injection | Marker spoofing |
| redact_bypass | DataLeak | Redaction bypass |
| obfuscation_bypass | Injection | Obfuscation bypass |
| unicode_bypass | Injection | Unicode bypass |
| ratelimit_scope_bypass | Config | Rate-limit scope bypass |
| flood_guard_reset | Config | Flood guard reset |
| webhook_verify | Config | Webhook verification bypass |
| skill_scanner_bypass | Config | Skill scanner bypass |

### CVE-Specific Modules (2026 Threat Intelligence)

| Module | CVE / Source | Description |
|------|-----------|------|
| gateway_hijack | CVE-2026-25253 | gatewayURL WebSocket hijacking → token theft |
| safebins_bypass | CVE-2026-28363 | GNU long-option abbreviation bypass of the safeBins allowlist → RCE |
| ws_auth_brute | CVE-2026-32025 | WebSocket authentication brute force + localhost rate-limit exemption |
| localhost_trust | ClawJacked | Authentication bypass via implicit localhost trust |
| guest_mode_abuse | Conscia audit | Guest Mode exposes dangerous API endpoints |
| mdns_leak | Conscia audit | mDNS/HTTP configuration parameter leakage |
| skill_supply_chain | ClawHavoc | Malicious Skill supply-chain attack detection (AMOS credential theft) |

---

## DAG Attack Chain Architecture

```
                        ┌─────────────────────┐
                        │   Level 0 (Recon)    │
                        │  CORS / WS / Auth    │
                        └─────────┬───────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │  Level 1 (Init) │ │ Level 1 (Cred)  │ │  Level 1 (Init) │
    │ SSRF / Eval /   │ │ APIKey / OAuth  │ │ Prompt / MCP /  │
    │ Pairing         │ │ Token Theft     │ │ Responses       │
    └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                   ┌─────────────────────────┐
                   │   Level 2 (Execution)   │
                   │  RCE / Hook / Tools /   │
                   │  Session Write          │
                   └────────────┬────────────┘
                                │
                   ┌────────────┼────────────┐
                   ▼                         ▼
         ┌─────────────────┐       ┌─────────────────┐
         │ Level 3 (Persis)│       │ Level 3 (Priv)  │
         │ Agent / Cron /  │       │ Approval / Node │
         │ Skill Poison    │       │ Config Tamper    │
         └────────┬────────┘       └────────┬────────┘
                  │                         │
                  └────────────┬────────────┘
                               ▼
                  ┌─────────────────────────┐
                  │   Level 4 (Exfil)       │
                  │  C2 / Transcript /      │
                  │  Memory Leak            │
                  └─────────────────────────┘
```

**Execution characteristics:**
- Kahn topological sort → level-by-level parallel execution
- `Semaphore` controls maximum concurrency
- `depends_on` — predecessor nodes must complete
- `fallback_for` — skip the fallback node if the parent node has findings
- `condition` — conditional execution based on earlier results
- `AttackGraph` — records each node's executed/skipped/fallback status and exports a Mermaid diagram

---

## Nuclei Templates

`nuclei-templates/` contains 24 standalone Nuclei-compatible YAML templates:

```bash
# Scan a single target
nuclei -t nuclei-templates/ -u http://TARGET_IP:PORT

# Scan a target list
nuclei -t nuclei-templates/ -l targets.txt

# Critical only
nuclei -t nuclei-templates/ -u http://TARGET_IP:PORT -severity critical
```

---

## Project Structure

```
catchclaw/
├── rust/
│   ├── Cargo.toml                 # Project configuration
│   └── src/
│       ├── main.rs                # CLI entry point (clap derive)
│       ├── config/mod.rs          # AppConfig + Profile + protocol constants
│       ├── chain/
│       │   ├── dag.rs             # DAG engine (topological sort + concurrency + AttackGraph)
│       │   └── chains.rs          # Definitions of the 78 attack chain nodes
│       ├── exploit/
│       │   ├── registry.rs        # ExploitMeta + inventory registration system
│       │   ├── base.rs            # ExploitCtx shared context + PayloadRegistry integration
│       │   └── *.rs               # Implementations of the 78 exploit modules
│       ├── platform/
│       │   ├── mod.rs             # PlatformProfile trait + TargetPlatform
│       │   ├── registry.rs        # PlatformRegistry (9 platform registrations)
│       │   └── profiles/          # Implementations of the 9 platform profiles
│       ├── scan/mod.rs            # Full scan + multi-target scan orchestration
│       ├── report/mod.rs          # JSON / HTML / Markdown report output
│       └── utils/
│           ├── types.rs           # Target / Finding / Severity / multi-target parsing
│           ├── http.rs            # HTTP client + false-positive filter
│           ├── ws.rs              # GatewayWsClient (WS + challenge)
│           ├── discovery.rs       # Port scanning + multi-platform service discovery
│           ├── payload.rs         # PayloadRegistry (YAML loading + directory merging)
│           └── mutate.rs          # Payload mutation engine
├── payloads/                      # 200+ external Payloads (YAML)
│   ├── ssrf.yaml                  # SSRF: AWS/GCP/Azure/IP bypass/protocol smuggling
│   ├── injection.yaml             # Command injection/shell metacharacters/encoding bypass
│   ├── prompt_inject.yaml         # Prompt injection/jailbreak/role override
│   ├── auth_bypass.yaml           # Token/Header/path traversal/default credentials
│   └── xss.yaml                   # XSS: reflected/event-based/filter bypass/polyglot
├── nuclei-templates/              # 24 Nuclei YAML templates
├── LICENSE                        # CatchClaw Strict Non-Commercial License v2.0
└── README.md
```

---

## Disclaimer

This tool is intended for **authorized security testing** only. Test only systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. The author is not responsible for any misuse.

## Author

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## License

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — commercial use is strictly prohibited; violators will be held liable.
