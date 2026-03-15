<div align="center">

# 🦞 LobsterGuard

**OpenClaw Security Assessment Tool**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)]()

31-chain automated attack suite for [OpenClaw](https://github.com/anthropics/open-claw) instances.

Fingerprint → Auth Bypass → Recon → Audit → Exploit → Report

</div>

---

## What is this?

LobsterGuard is a purpose-built penetration testing tool targeting **OpenClaw** (the open-source AI coding agent platform). It automates the full attack lifecycle — from asset discovery to RCE verification — through 31 chained exploit modules covering the OpenClaw Gateway WebSocket API, HTTP endpoints, and integration surfaces.

Built for security researchers, red teamers, and OpenClaw operators who need to validate their deployment security.

## Features

- **Asset Discovery** — Shodan / FOFA integration for internet-wide OpenClaw hunting
- **Fingerprinting** — Zero-auth OpenClaw detection and version identification
- **Auth Testing** — No-auth probe + token brute force with built-in wordlist
- **Recon** — HTTP endpoint enumeration + WebSocket method discovery
- **Config Audit** — 15+ misconfiguration checks via authenticated API
- **31 Exploit Chains** — Full attack suite from SSRF to RCE (see below)
- **Interactive Shell** — msfconsole-style REPL with per-chain execution
- **23 Nuclei Templates** — Drop into CI/CD pipelines
- **Reporting** — JSON + HTML output with severity classification

## Quick Start

```bash
# Build
go build -o lobster-guard ./cmd/lobster-guard/

# Full scan against a target
./lobster-guard scan -t 10.0.0.1:18789

# With known token
./lobster-guard scan -t 10.0.0.1:18789 --token "your-gateway-token"

# Exploit-only mode
./lobster-guard exploit -t 10.0.0.1:18789 --token "tok"

# Interactive shell
./lobster-guard shell
```

## Usage

```
Usage:
  lobster-guard [command]

Commands:
  scan          Full pipeline: fingerprint + auth + brute + recon + audit + exploit
  fingerprint   Detect OpenClaw instances
  auth          Auth test: no-auth + brute force
  recon         Endpoint + WS method enumeration + version detect
  audit         Config audit (needs token)
  exploit       31-chain OpenClaw attack suite
  discover      Asset discovery via Shodan/FOFA
  shell         Interactive shell (msfconsole-style)

Flags:
  -t, --target string     Target host:port
  -T, --targets string    File with targets, one per line
  -c, --concurrency int   Concurrent target scans (default 1)
  -o, --output string     Output JSON report path
      --token string      Gateway token
      --tls               Use HTTPS/WSS
      --timeout int       HTTP timeout in seconds (default 10)
```

### Interactive Shell

```
$ ./lobster-guard shell

LobsterGuard interactive shell. Type 'help' for commands.
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
```

### Asset Discovery

```bash
# Shodan
./lobster-guard discover --shodan-key "YOUR_KEY" -o targets.txt

# FOFA
./lobster-guard discover --fofa-email "you@x.com" --fofa-key "KEY" -o targets.txt

# Then scan all discovered targets
./lobster-guard scan -T targets.txt -c 10
```

## Attack Chains

| # | Chain | Severity | Description |
|---|-------|----------|-------------|
| 0 | Platform Fingerprint | Info | Zero-auth OpenClaw detection |
| 1 | SSRF | Critical | browser.request/navigate → cloud metadata (AWS/GCP/Azure/DO) |
| 2 | eval() Injection | Critical | Code execution via eval/exec in tool parameters |
| 3 | API Key Theft | Critical | Extract provider API keys via config/env endpoints |
| 4 | Pairing Brute Force | High | DM pairing code brute force (6-digit) |
| 5 | Cron Bypass | High | Cron deny list bypass + persistence |
| 6 | Prompt Injection | High | System prompt extraction + instruction override |
| 7 | RCE Reachability | Critical | system.run command execution probe |
| 8 | Hook Injection | Critical | Webhook endpoint injection for command execution |
| 9 | Secret Extraction | Critical | secrets.list + secrets.get plaintext theft |
| 10 | Config Tampering | High | config.set write access to security settings |
| 11 | Tool Invocation | Critical | tools.invoke bypasses chat-layer security |
| 12 | Session Hijack | High | sessions.preview IDOR + cross-session injection |
| 13 | CORS Bypass | Medium | Origin reflection → cross-origin WS/API access |
| 14 | Channel Injection | High | Mattermost/Slack/Discord unsigned command injection |
| 15 | Log Disclosure | Medium | logs.query credential/sensitive data leak |
| 16 | Patch Escape | Critical | apply_patch path traversal → arbitrary file write |
| 17 | WS Hijack | High | Cross-origin WebSocket upgrade + token replay |
| 18 | Agent Injection | Critical | agents.create/update backdoor + system prompt leak |
| 19 | OAuth Abuse | High | Slack OAuth redirect hijack + state fixation |
| 20 | Responses API | Critical | /v1/responses auth bypass + tool injection |
| 21 | WS Fuzz | Medium | Malformed JSON-RPC + method injection |
| 22 | Agent File Inject | Critical | Persistent prompt backdoor via agents.files.set |
| 23 | Session File Write | Critical | Arbitrary file write via sessions.patch + compact |
| 24 | Approval Hijack | Critical | Prefix ID matching + exec policy tamper |
| 25 | Talk Secrets | Critical | API key exfil via talk.config(includeSecrets) |
| 26 | Browser SSRF | High | Internal dispatch via browser.request |
| 27 | Secrets Resolve | Critical | secrets.resolve plaintext extraction (internal injection API) |
| 28 | Transcript Theft | High | Unredacted session history + tool output theft |
| 29 | Rogue Node | Critical | Self-approved node pairing → command interception |
| 30 | Full RCE | Critical | nodes.list → self-approve → node.invoke system.run |

## Nuclei Templates

23 ready-to-use templates for automated scanning:

```bash
# Scan single target
nuclei -t nuclei-templates/ -u http://10.0.0.1:18789

# Scan target list
nuclei -t nuclei-templates/ -l targets.txt

# Critical only
nuclei -t nuclei-templates/ -u http://target:18789 -severity critical
```

Templates cover: detection, no-auth, default tokens, weak tokens, CORS, sessions exposure, exec approvals, hooks, OAuth redirect, WebSocket, Slack/Mattermost/Discord injection, Responses API, agent files, rogue node, secrets resolve, transcript theft, full RCE, and more.

## Project Structure

```
lobster-guard/
├── cmd/lobster-guard/     # CLI entrypoint
├── pkg/
│   ├── audit/             # Config audit checks
│   ├── auth/              # No-auth + brute force
│   ├── chain/             # Attack chain orchestrator
│   ├── discovery/         # Shodan/FOFA asset discovery
│   ├── exploit/           # 30 exploit modules (4500+ lines)
│   ├── interactive/       # msfconsole-style REPL shell
│   ├── recon/             # Endpoint + WS method enumeration
│   ├── report/            # JSON + HTML report generation
│   ├── scanner/           # Fingerprinting engine
│   └── utils/             # HTTP client, WS client, types
├── nuclei-templates/      # 23 Nuclei YAML templates
└── rules/                 # Default credential wordlists
```

## Disclaimer

This tool is intended for **authorized security testing only**. Use it only against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse.

## Author

**coff0xc**

## License

GPL-3.0
