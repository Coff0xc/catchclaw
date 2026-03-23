<h1 align="center">🦞 CatchClaw v5.2.0</h1>

<p align="center">
  <b>Automated Security Assessment Tool for OpenClaw / Open-WebUI AI Coding Platforms</b><br>
  <sub>72 DAG Attack Chains | 72 Exploit Modules | ATT&CK Phase Mapping | Async Tokio Engine | Attack Graph Visualization</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md"><b>English</b></a> ·
  <a href="README_JA.md">日本語</a> ·
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
  <img src="https://img.shields.io/badge/Version-5.2.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Rust-Edition_2024-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/DAG_Chains-72-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Async-Tokio-4CAF50?style=flat-square" alt="Tokio">
  <img src="https://img.shields.io/badge/Exploits-72_Modules-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/License-Non--Commercial--v2.0-green?style=flat-square" alt="License">
</p>

---

> **⚠️ COMMERCIAL USE STRICTLY PROHIBITED**
>
> Licensed under **CatchClaw Strict Non-Commercial License v2.0**.
>
> **ALL commercial use is STRICTLY PROHIBITED without prior written authorization from the copyright holder (Coff0xc).** Violators will be prosecuted.
>
> Prohibited activities include but are not limited to:
> - Selling, sublicensing, or renting the Software or derivative works
> - Using the Software for SaaS, pentesting services, consulting, or any paid service
> - Integrating into commercial products, platforms, or tools
> - Training commercial AI/ML models
> - Rebranding, repackaging, or white-labeling for distribution
> - Any activity that directly or indirectly generates revenue
>
> **The copyright holder reserves the right of retroactive enforcement with NO time limitation, including recovery of all profits, legal fees, and punitive damages.**
>
> See [LICENSE](LICENSE).

---

## Highlights

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CatchClaw v5.2.0                                │
├────────────────────────────────────────────────────────────────────────────┤
│  ● 72 DAG Attack Chains  ● 72 Exploit Modules   ● Async Tokio Engine    │
│  ● ATT&CK 9-Phase Map   ● Mermaid Attack Graph  ● JSON/HTML/MD Reports  │
│  ● Kahn Topological Sort ● Semaphore Concurrency ● Condition/Fallback    │
│  ● Multi-Target (CIDR)  ● Port Scan / Discovery ● 200+ External Payloads│
├────────────────────────────────────────────────────────────────────────────┤
│  Attack Surface: Gateway WS API | HTTP REST | OAuth | Webhook | Node     │
│  Coverage: SSRF | RCE | Key Theft | Session Hijack | Privesc | Persist   │
│  New: C2 Exfil | Skill Poison | Agent Inject | MCP Inject | DNS Rebind  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [72 Exploit Modules](#59-exploit-modules)
- [DAG Attack Chain Architecture](#dag-attack-chain-architecture)
- [Nuclei Templates](#nuclei-templates)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)

---

## Overview

**CatchClaw** is a Rust-based automated security assessment tool purpose-built for [OpenClaw](https://github.com/anthropics/open-claw) / Open-WebUI AI coding agent platforms. It executes 59 exploit modules orchestrated through a DAG (Directed Acyclic Graph) attack chain, covering the full ATT&CK lifecycle from reconnaissance to data exfiltration.

Built on Tokio async runtime, the DAG engine uses Kahn's topological sort for level-by-level concurrent execution with Semaphore-bounded concurrency, conditional execution, and fallback nodes. Attack results are visualized as Mermaid flowcharts.

### Why CatchClaw?

| Scenario | Manual Testing | CatchClaw |
|----------|---------------|-----------|
| **Vulnerability Validation** | Write PoCs one by one | 59 chains with automated orchestration |
| **Attack Surface Coverage** | Experience-dependent | WS + HTTP + OAuth + Webhook + Node full coverage |
| **Dependency Chain Discovery** | Hard to track | DAG auto-discovers vulnerability dependency paths |
| **Result Visualization** | Manual compilation | Mermaid attack graph + JSON/HTML/Markdown report |
| **CI/CD Integration** | None | 24 Nuclei templates plug-and-play |
| **Multi-Target Scanning** | Test one at a time | CIDR, IP range, target file batch scanning |
| **Service Discovery** | Requires nmap | Built-in port scan + OpenClaw fingerprinting |

---

## Core Features

<table>
<tr>
<td width="50%">

### Attack Engine

- **72 Exploit Modules** — 10 categories, `inventory` macro auto-registration
- **72 DAG Attack Chains** — 9 ATT&CK phases, automated orchestration
- **Kahn Topological Sort** — Level-by-level concurrent execution with dependency resolution
- **Condition/Fallback Nodes** — Dynamic path decisions based on prior results
- **Attack Graph Visualization** — Mermaid export with hit/skip/fallback status

</td>
<td width="50%">

### Protocol Support

- **WebSocket Gateway** — Challenge handshake detection, JSON-RPC calls
- **HTTP REST** — Redirect following disabled to prevent OAuth 302 false positives
- **False Positive Elimination** — Challenge page / SPA fallback / LLM refusal detection
- **TLS Support** — rustls backend, `--tls` enables HTTPS/WSS
- **Multi-Format Reports** — JSON + HTML (dark theme) + Markdown

</td>
</tr>
<tr>
<td width="50%">

### Scanning Enhancements

- **Multi-Target Scanning** — CIDR (/24), IP range, comma-separated, target file
- **Port Scanning** — TCP connect scan + custom port ranges
- **Service Discovery** — OpenClaw fingerprinting (API/WebSocket/health)
- **200+ Payloads** — SSRF/Injection/Prompt/Auth/XSS external YAML library
- **Scan Config** — TOML config file + Profile presets + proxy support

</td>
<td width="50%">

### CLI Experience

- **`--profile`** — Use preset scan configs (quick/stealth/full)
- **`--severity-filter`** — Filter results by severity level
- **`--format`** — Output format: json/html/markdown
- **`--dry-run`** — Preview DAG execution plan without scanning
- **`--targets-file`** — Batch target file input

</td>
</tr>
</table>

---

## Installation

### Build from Source

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Debug build
cargo build

# Release build (optimized + stripped)
cargo build --release

# Binary at target/release/catchclaw
```

### Requirements

- Rust Edition 2024 (rustc 1.85+)
- Windows / Linux / macOS

---

## Quick Start

```bash
# List all registered modules
catchclaw list

# Full scan
catchclaw scan -t TARGET_IP:PORT

# Scan with JSON report output
catchclaw scan -t TARGET_IP:PORT -o report.json

# HTML report output
catchclaw scan -t TARGET_IP:PORT -o report.html --format html

# Multi-target scan (CIDR)
catchclaw scan --targets "192.168.1.0/24:8080"

# Batch scan from file
catchclaw scan -f targets.txt -o results.json

# Use a scan profile
catchclaw scan -t TARGET_IP:PORT --profile stealth

# Show only critical/high findings
catchclaw scan -t TARGET_IP:PORT --severity-filter critical,high

# Preview execution plan
catchclaw scan -t TARGET_IP:PORT --dry-run

# Scan with authentication token
catchclaw scan -t TARGET_IP:PORT --token "your-gateway-token"

# Execute full attack chain
catchclaw exploit -t TARGET_IP:PORT --token xxx

# Execute a single chain node
catchclaw exploit -t TARGET_IP:PORT --chain-id 30
```

---

## CLI Usage

```
CatchClaw v5.2.0 — OpenClaw Security Assessment Tool

Usage: catchclaw <COMMAND>

Commands:
  scan      Full security scan (build DAG → execute → summarize)
  exploit   Execute attack chains (full DAG or single node)
  list      List all registered exploit modules
  config    Show current configuration

Scan Flags:
  -t, --target <HOST:PORT>     Target address (single target)
      --targets <SPEC>         Multi-target: comma-separated, CIDR, or IP range
  -f, --targets-file <FILE>    Target file (one host:port per line)
      --token <TOKEN>          Gateway Token (or CATCHCLAW_TOKEN env var)
      --timeout <SECS>         Request timeout in seconds (default 10)
  -o, --output <FILE>          Report output path
      --format <FMT>           Output format: json | html | markdown (default json)
      --concurrency <N>        Max concurrent workers (default 10)
      --tls                    Use HTTPS/WSS
      --callback <URL>         SSRF callback URL
      --profile <NAME>         Use a profile from config file
      --severity-filter <SEV>  Filter by severity: critical,high,medium,low,info
      --dry-run                Preview DAG execution plan
      --config <FILE>          Config file path (TOML/YAML/JSON)

Exploit Flags:
  -t, --target <HOST:PORT>     Target address
      --token <TOKEN>          Gateway Token
      --chain-id <ID>          Run a single chain node by ID
      --concurrency <N>        Max concurrent workers (default 10)
      --tls                    Use HTTPS/WSS
```

---

## 72 Exploit Modules

Grouped by ATT&CK phase and attack category:

### Recon

| Module | Category | Description |
|--------|----------|-------------|
| cors_bypass | Config | Origin reflection → cross-origin WS/API access |
| ws_hijack | Transport | Cross-origin WebSocket upgrade + token replay |
| auth_mode_abuse | Auth | Authentication mode detection and abuse |
| log_disclosure | DataLeak | logs.query credential/sensitive data exposure |
| hidden_content | DataLeak | Hidden content discovery |
| origin_wildcard | Config | Origin wildcard configuration detection |

### Initial Access

| Module | Category | Description |
|--------|----------|-------------|
| ssrf | SSRF | browser.request/navigate → cloud metadata (AWS/GCP/Azure) |
| eval_inject | Injection | eval/exec code execution via tool parameters |
| prompt_inject | Injection | System prompt extraction + instruction override |
| mcp_inject | Injection | MCP plugin injection |
| pairing_brute | Auth | DM pairing code 6-digit brute-force |
| oauth_abuse | Auth | Slack OAuth redirect hijacking |
| responses_exploit | API | /v1/responses auth bypass + tool injection |
| ws_fuzz | Fuzz | Malformed JSON-RPC + method injection |
| acp_bypass | Auth | ACP access control bypass |
| ssrf_rebind | SSRF | DNS rebind SSRF |
| ssrf_proxy_bypass | SSRF | Proxy bypass SSRF |
| browser_request | SSRF | Browser request internal dispatch |
| csrf_no_origin | Config | No-Origin validation CSRF |

### Credential Access

| Module | Category | Description |
|--------|----------|-------------|
| apikey_steal | Credential | Provider API key extraction |
| oauth_token_theft | Credential | OAuth token theft |
| secret_extract | Credential | secrets.list + secrets.get plaintext theft |
| secrets_resolve | Credential | secrets.resolve internal injection API |
| talk_secrets | Credential | talk.config(includeSecrets) key exfiltration |

### Execution

| Module | Category | Description |
|--------|----------|-------------|
| rce | RCE | system.run command execution probe |
| hook_inject | RCE | Webhook endpoint injection for command execution |
| tools_invoke | RCE | tools.invoke bypasses Chat layer security |
| keychain_cmd_inject | RCE | Keychain command injection |
| qmd_cmd_inject | RCE | QMD command injection |
| exec_race_toctou | RCE | Execution race condition (TOCTOU) |
| exec_socket_leak | RCE | Execution socket leak |

### Persistence

| Module | Category | Description |
|--------|----------|-------------|
| agent_inject | Injection | agents.create/update backdoor + system prompt leak |
| agent_file_inject | Injection | agents.files.set persistent prompt backdoor |
| channel_inject | Injection | Mattermost/Slack/Discord unsigned command injection |
| skill_poison | Injection | Skill poisoning |
| cron_bypass | Persistence | Cron blacklist bypass + persistence |
| session_file_write | RCE | sessions.patch arbitrary file write |
| patch_escape | RCE | apply_patch path traversal → arbitrary file write |
| link_template_inject | Injection | Link template injection |

### Privilege Escalation

| Module | Category | Description |
|--------|----------|-------------|
| approval_hijack | Auth | Prefix ID matching + execution policy tampering |
| config_tamper | Config | config.set security configuration write |
| rogue_node | RCE | Self-approve node pairing → command interception |
| silent_pair_abuse | Auth | Silent pairing abuse |
| auth_disable_leak | Auth | Auth disable leak |

### Lateral Movement / Exfiltration

| Module | Category | Description |
|--------|----------|-------------|
| session_hijack | DataLeak | sessions.preview IDOR + cross-session injection |
| transcript_theft | DataLeak | Session transcript theft |
| memory_data_leak | DataLeak | Memory data leak |
| c2_exfil | DataLeak | C2 data exfiltration |
| browser_upload_traversal | RCE | Browser upload path traversal |
| secret_exec_abuse | RCE | Secret execution abuse |
| bypass_soul | Injection | Soul bypass |
| marker_spoof | Injection | Marker spoofing |
| redact_bypass | DataLeak | Redaction bypass |
| obfuscation_bypass | Injection | Obfuscation bypass |
| unicode_bypass | Injection | Unicode bypass |
| ratelimit_scope_bypass | Config | Rate limit scope bypass |
| flood_guard_reset | Config | Flood guard reset |
| webhook_verify | Config | Webhook verification bypass |
| skill_scanner_bypass | Config | Skill scanner bypass |

### CVE-Targeted Modules (2026 Threat Intelligence)

| Module | CVE / Source | Description |
|--------|-------------|-------------|
| gateway_hijack | CVE-2026-25253 | gatewayURL WebSocket hijacking → token theft |
| safebins_bypass | CVE-2026-28363 | GNU long-option abbreviation safeBins bypass → RCE |
| ws_auth_brute | CVE-2026-32025 | WebSocket auth brute-force + localhost rate limit exempt |
| localhost_trust | ClawJacked | Localhost implicit trust authentication bypass |
| guest_mode_abuse | Conscia audit | Guest Mode dangerous API endpoint exposure |
| mdns_leak | Conscia audit | mDNS/HTTP configuration parameter leakage |
| skill_supply_chain | ClawHavoc | Malicious skill supply chain attack detection (AMOS) |

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

**Execution Features:**
- Kahn's topological sort → level-by-level concurrent execution
- `Semaphore` controls max concurrency
- `depends_on` — predecessor nodes must complete
- `fallback_for` — skip fallback node if parent found findings
- `condition` — conditional execution based on prior results
- `AttackGraph` — records hit/skip/fallback status per node, exports Mermaid diagram

---

## Nuclei Templates

`nuclei-templates/` contains 24 standalone Nuclei-compatible YAML templates:

```bash
# Scan a single target
nuclei -t nuclei-templates/ -u http://TARGET:PORT

# Scan a target list
nuclei -t nuclei-templates/ -l targets.txt

# Critical only
nuclei -t nuclei-templates/ -u http://TARGET:PORT -severity critical
```

---

## Project Structure

```
catchclaw/
├── rust/
│   ├── Cargo.toml                 # Project configuration
│   └── src/
│       ├── main.rs                # CLI entry point (clap derive)
│       ├── config/mod.rs          # AppConfig + profiles + protocol constants
│       ├── chain/
│       │   ├── dag.rs             # DAG engine (topo sort + concurrency + AttackGraph)
│       │   └── chains.rs          # 59 attack chain node definitions
│       ├── exploit/
│       │   ├── registry.rs        # ExploitMeta + inventory registration system
│       │   ├── base.rs            # ExploitCtx shared context + PayloadRegistry
│       │   └── *.rs               # 59 exploit module implementations
│       ├── scan/mod.rs            # Full scan + multi-target orchestration
│       ├── report/mod.rs          # JSON / HTML / Markdown report output
│       └── utils/
│           ├── types.rs           # Target / Finding / Severity / multi-target parsing
│           ├── http.rs            # HTTP client + false positive filters
│           ├── ws.rs              # GatewayWsClient (WS + challenge detection)
│           ├── discovery.rs       # Port scanning + OpenClaw service discovery
│           ├── payload.rs         # PayloadRegistry (YAML loading + directory merge)
│           └── mutate.rs          # Payload mutation engine
├── payloads/                      # 200+ external payloads (YAML)
│   ├── ssrf.yaml                  # SSRF: AWS/GCP/Azure/IP bypass/protocol smuggling
│   ├── injection.yaml             # Command injection/shell metachar/encoding bypass
│   ├── prompt_inject.yaml         # Prompt injection/jailbreak/role override
│   ├── auth_bypass.yaml           # Token/header/path traversal/default creds
│   └── xss.yaml                   # XSS: reflected/event/filter bypass/polyglot
├── nuclei-templates/              # 24 Nuclei YAML templates
├── LICENSE                        # CatchClaw Strict Non-Commercial License v2.0
└── README.md
```

---

## Disclaimer

This tool is intended for **authorized security testing only**. Only test systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. The author assumes no responsibility for any misuse.

## Author

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## License

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — Commercial use strictly prohibited.
