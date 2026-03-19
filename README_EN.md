<h1 align="center">🦞 CatchClaw</h1>

<p align="center">
  <b>Dedicated Security Assessment Tool for OpenClaw</b><br>
  <sub>31 Attack Chains | 23 Nuclei Templates | Interactive Shell | Shodan/FOFA Asset Discovery | Full-Pipeline Automation</sub>
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
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Chains-31-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Nuclei-23_Templates-4CAF50?style=flat-square" alt="Nuclei">
  <img src="https://img.shields.io/badge/Exploits-30_Modules-orange?style=flat-square" alt="Exploits">
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



## Highlights

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        CatchClaw v1.0.0                              │
├──────────────────────────────────────────────────────────────────────────┤
│  ● 31 Attack Chains    ● 30 Exploit Modules    ● 23 Nuclei Templates    │
│  ● Interactive Shell   ● Shodan/FOFA Discovery ● JSON + HTML Reports    │
│  ● Full WebSocket Cov. ● Zero-Auth Fingerprint ● Multi-Target Concurr.  │
├──────────────────────────────────────────────────────────────────────────┤
│  Attack Surface: Gateway WS API | HTTP REST | OAuth | Webhook | Node Pairing   │
│  Coverage: SSRF | RCE | Key Theft | Session Hijack | Privesc | Persist | Data Leak   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Interactive Shell](#interactive-shell)
- [31 Attack Chains](#31-attack-chains)
- [Nuclei Templates](#nuclei-templates)
- [Asset Discovery](#asset-discovery)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [Author](#author)
- [License](#license)

---

## Overview

**CatchClaw** is an automated penetration testing tool specifically targeting [OpenClaw](https://github.com/anthropics/open-claw), the open-source AI coding agent platform. It covers the complete attack lifecycle from asset discovery to RCE validation, using 31 chained exploit modules to comprehensively test the security of OpenClaw Gateway WebSocket API, HTTP endpoints, and integration interfaces.

### Why CatchClaw?

| Scenario | Manual Testing | CatchClaw |
|----------|---------------|-------------|
| **Target Discovery** | Manual Shodan/FOFA search | `discover` one-click aggregation |
| **Instance Identification** | Probe HTTP one by one | Zero-auth automatic fingerprinting |
| **Auth Testing** | Write custom brute-force scripts | Built-in wordlist + smart delay |
| **Vuln Validation** | Manually craft PoC one by one | 31-chain automated validation |
| **Attack Surface Coverage** | Experience-dependent | WS + HTTP + OAuth + Webhook + Node full coverage |
| **Report Output** | Manual compilation | JSON + HTML one-click generation |
| **CI/CD Integration** | None | 23 Nuclei templates plug-and-play |

---

## Core Features

<table>
<tr>
<td width="50%">

### Reconnaissance & Discovery

- **Shodan / FOFA Asset Discovery** — Internet-wide OpenClaw instance search
- **Zero-Auth Fingerprinting** — Auto-detect OpenClaw and extract version info
- **HTTP Endpoint Enumeration** — Comprehensive REST API route scanning
- **WebSocket Method Discovery** — Enumerate available Gateway WS methods
- **Auth Mode Detection** — Identify no-auth / token / OAuth modes

</td>
<td width="50%">

### Attack & Exploitation

- **31 Attack Chains** — From SSRF to full RCE chains
- **Automated Exploit Orchestration** — Chain Orchestrator executes in sequence
- **Self-Approve RCE** — exec.approval.request → self-approve → node.invoke
- **Key Theft** — secrets.resolve / talk.config / API key extraction
- **Persistent Backdoors** — Agent injection + file write + Cron bypass

</td>
</tr>
<tr>
<td width="50%">

### Security Auditing

- **15+ Config Audit Items** — Auth, permissions, encryption, logging, etc.
- **Token Brute-Force** — Built-in high-frequency weak password wordlist + custom wordlist
- **CORS Detection** — Origin reflection + credential leak validation
- **OAuth Security** — Redirect hijacking + State fixation attacks

</td>
<td width="50%">

### Tools & Reporting

- **Interactive Shell** — msfconsole-style REPL, chain-by-chain execution
- **23 Nuclei Templates** — Direct CI/CD pipeline integration
- **JSON + HTML Reports** — Severity classification + remediation advice
- **Multi-Target Concurrency** — `-c` flag controls concurrency count

</td>
</tr>
</table>

---

## Quick Start

### Requirements

- Go 1.22+
- Network-reachable OpenClaw instance

### Build & Install

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw
go build -o catchclaw ./cmd/catchclaw/
```

### Basic Usage

```bash
# Full scan
./catchclaw scan -t 10.0.0.1:18789

# Scan with token
./catchclaw scan -t 10.0.0.1:18789 --token "your-gateway-token"

# Exploit only
./catchclaw exploit -t 10.0.0.1:18789 --token "tok"

# Interactive shell
./catchclaw shell
```

---

## Usage

```
Usage:
  catchclaw [command]

Commands:
  scan          Full pipeline: fingerprint + auth + brute-force + recon + audit + exploit
  fingerprint   Detect OpenClaw instance
  auth          Auth testing: no-auth detection + token brute-force
  recon         Endpoint enumeration + WS method discovery + version detection
  audit         Configuration audit (requires token)
  exploit       Execute all 31 attack chains
  discover      Shodan/FOFA asset discovery
  shell         Interactive shell (msfconsole style)

Flags:
  -t, --target string     Target host:port
  -T, --targets string    Target list file (one per line)
  -c, --concurrency int   Concurrent scan count (default 1)
  -o, --output string     JSON report output path
      --token string      Gateway Token
      --tls               Use HTTPS/WSS
      --timeout int       HTTP timeout in seconds (default 10)
```

---

## Interactive Shell

```
$ ./catchclaw shell

CatchClaw interactive shell. Type 'help' for commands.
lobster🦞> target 10.0.0.1:18789
[*] Target set: 10.0.0.1:18789
lobster🦞> token my-gateway-token
[*] Token set: my-...ken
lobster🦞> chain 30
[*] Running chain 30: Full RCE chain (self-approve + node.invoke)
lobster🦞> exploit
[*] ═══ OpenClaw Attack Chain Orchestration ═══
lobster🦞> chains
Chain  0: Platform fingerprint (zero-auth)
Chain  1: SSRF + cloud metadata
...
Chain 30: Full RCE chain (self-approve + node.invoke)
lobster🦞> results
lobster🦞> export report.json
```

---

## 31 Attack Chains

| # | Chain | Severity | Description |
|---|-------|----------|-------------|
| 0 | Platform Fingerprint | Info | Zero-auth OpenClaw detection |
| 1 | SSRF | Critical | browser.request/navigate → cloud metadata (AWS/GCP/Azure/DO) |
| 2 | eval() Injection | Critical | eval/exec code execution via tool parameters |
| 3 | API Key Theft | Critical | Extract provider API keys via config/env endpoints |
| 4 | Pairing Code Brute-Force | High | DM pairing code 6-digit brute-force |
| 5 | Cron Bypass | High | Cron blacklist bypass + persistence |
| 6 | Prompt Injection | High | System prompt extraction + instruction override |
| 7 | RCE Reachability | Critical | system.run command execution probe |
| 8 | Hook Injection | Critical | Webhook endpoint injection to execute commands |
| 9 | Secret Extraction | Critical | secrets.list + secrets.get plaintext theft |
| 10 | Config Tampering | High | config.set write to security configuration |
| 11 | Direct Tool Invocation | Critical | tools.invoke bypasses Chat layer security |
| 12 | Session Hijacking | High | sessions.preview IDOR + cross-session injection |
| 13 | CORS Bypass | Medium | Origin reflection → cross-origin WS/API access |
| 14 | Channel Injection | High | Mattermost/Slack/Discord unsigned command injection |
| 15 | Log Leakage | Medium | logs.query credential/sensitive data exposure |
| 16 | Patch Escape | Critical | apply_patch path traversal → arbitrary file write |
| 17 | WS Hijacking | High | Cross-origin WebSocket upgrade + token replay |
| 18 | Agent Injection | Critical | agents.create/update backdoor + system prompt leak |
| 19 | OAuth Abuse | High | Slack OAuth redirect hijacking + State fixation |
| 20 | Responses API | Critical | /v1/responses auth bypass + tool injection |
| 21 | WS Fuzz | Medium | Malformed JSON-RPC + method injection |
| 22 | Agent File Injection | Critical | agents.files.set persistent prompt backdoor |
| 23 | Session File Write | Critical | sessions.patch + compact arbitrary file write |
| 24 | Approval Hijacking | Critical | Prefix ID matching + execution policy tampering |
| 25 | Talk Secret | Critical | talk.config(includeSecrets) API key exfiltration |
| 26 | Browser SSRF | High | browser.request internal dispatch |
| 27 | Secrets Resolve | Critical | secrets.resolve plaintext extraction (internal injection API) |
| 28 | Session Record Theft | High | Unsanitized session history + tool output theft |
| 29 | Rogue Node | Critical | Self-approve node pairing → command interception |
| 30 | Full RCE | Critical | nodes.list → self-approve → node.invoke system.run |

---

## Nuclei Templates

23 ready-to-use templates, directly integrable into CI/CD:

```bash
# Scan a single target
nuclei -t nuclei-templates/ -u http://10.0.0.1:18789

# Scan a target list
nuclei -t nuclei-templates/ -l targets.txt

# Critical only
nuclei -t nuclei-templates/ -u http://target:18789 -severity critical
```

Coverage: instance detection, no-auth, default token, weak token, CORS, session exposure, execution approval, webhook, OAuth redirect, WebSocket, Slack/Mattermost/Discord injection, Responses API, agent files, rogue node, secret resolution, session theft, full RCE, and more.

---

## Asset Discovery

```bash
# Shodan
./catchclaw discover --shodan-key "YOUR_KEY" -o targets.txt

# FOFA
./catchclaw discover --fofa-email "you@x.com" --fofa-key "KEY" -o targets.txt

# Scan all discovered targets
./catchclaw scan -T targets.txt -c 10
```

---

## Project Structure

```
catchclaw/
├── cmd/catchclaw/     # CLI entry point
├── pkg/
│   ├── audit/             # Configuration auditing
│   ├── auth/              # No-auth detection + token brute-force
│   ├── chain/             # Attack chain orchestrator
│   ├── discovery/         # Shodan/FOFA asset discovery
│   ├── exploit/           # 30 exploit modules (4500+ lines)
│   ├── interactive/       # msfconsole-style interactive shell
│   ├── recon/             # Endpoint + WS method enumeration
│   ├── report/            # JSON + HTML report generation
│   ├── scanner/           # Fingerprinting engine
│   └── utils/             # HTTP client, WS client, type definitions
├── nuclei-templates/      # 23 Nuclei YAML templates
└── rules/                 # Default credential wordlists
```

---

## Disclaimer

This tool is intended for **authorized security testing only**. Only test systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. The author assumes no responsibility for any misuse.

## Author

**coff0xc**

## License

[GPL-3.0](LICENSE)
