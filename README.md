<h1 align="center">🦞 CatchClaw</h1>

<p align="center">
  <b>Authorized security assessment for self-hosted AI / LLM platforms</b><br>
  <sub>Go v6.0.0 · 412 modules · 25 platform profiles · ATT&amp;CK-mapped DAG · Nuclei · OSINT · MCP</sub>
</p>

<p align="center">
  <a href="README.md"><b>English</b></a>
  · <a href="go/README.md">Go details</a>
  · <a href="README_JA.md">日本語</a>
  · <a href="README_RU.md">Русский</a>
  · <a href="README_DE.md">Deutsch</a>
  · <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/catchclaw/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/catchclaw/ci.yml?branch=master&style=flat-square&label=CI" alt="CI"></a>
  <a href="https://github.com/Coff0xc/catchclaw/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/catchclaw?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/catchclaw/issues"><img src="https://img.shields.io/github/issues/Coff0xc/catchclaw?style=flat-square" alt="Issues"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Non--Commercial%20v2.0-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-6.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/modules-412-FF6B6B?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/profiles-25-9B59B6?style=flat-square" alt="Profiles">
  <img src="https://img.shields.io/badge/chains-42-orange?style=flat-square" alt="Chains">
</p>

---

> **Legal risk / 法律风险（worldwide）**
>
> CatchClaw is dual-use. Run it only on systems you own or for which you already have **prior written authorization**. Unauthorized scanning or access is a crime or civil wrong **under the law of every applicable jurisdiction** — the place you act from, the place the target and its data sit, your nationality, and any country of transit or export. No country is exempt. You bear all legal risk. Commercial use is prohibited without written authorization from Coff0xc.
>
> 仅可在你拥有或已事先取得权利人**明确书面授权**的系统上运行。未经授权的扫描或访问，在**任何适用法域**均可构成犯罪或侵权（行为地、目标地、国籍地、过境地与出口管制地的法律可同时适用）。你承担全部法律风险。未经 Coff0xc 书面授权禁止商业使用。本仓库的版权许可准据法**不限制**任何国家刑法或监管法对你行为的适用。
>
> **[LEGAL.md](LEGAL.md)** · **[LICENSE](LICENSE)** · **[SECURITY.md](SECURITY.md)**

Source lives in [`go/`](go/) (v6.0.0). Localized READMEs may lag; this file is authoritative. The v5 Rust tree is not on `master` (git history / tag `v5.2.0`).

---

## What CatchClaw does

CatchClaw is a **single-binary assessment toolkit** for self-hosted AI infrastructure: chat UIs, agent platforms, inference servers, vector databases, and MLOps consoles.

On an authorized target it can:

1. **Find** the service (port scan + keyword fingerprint across 25 profiles).
2. **Probe** known-bad paths, default credentials, unauthenticated APIs, and CVE-shaped HTTP checks.
3. **Chain** multi-stage attacks that pass stolen tokens and IDs between steps.
4. **Report** JSON / HTML / Markdown plus an optional Mermaid attack graph.
5. **Hand off** the same engine to Nuclei templates, Shodan/FOFA/Hunter, or an MCP-connected assistant.

Hits are **unverified signals** (status codes and body keywords). Reproduce before you treat them as confirmed vulnerabilities.

```
  discover / OSINT                 scan / exploit / chain
  ┌──────────────┐                 ┌──────────────────────────┐
  │ ports +      │  authorized     │  DAG (Kahn + semaphore)  │
  │ fingerprint  │  target  ───►   │  101 exploits            │
  └──────────────┘                 │  269 HTTP checks         │
                                   │  42 state-passing chains │
  nuclei  /  mcp                   └────────────┬─────────────┘
  ┌──────────────┐                              ▼
  │ templates /  │                     JSON · HTML · Markdown
  │ AI assistant │                     Mermaid graph
  └──────────────┘
```

---

## Features

<table>
<tr>
<td width="50%" valign="top">

### Assessment engine

- **412 registered modules** — 101 handwritten exploits, 269 HTTP checks, 42 chains (`catchclaw list`)
- **ATT&CK-style phases** — Recon → Initial Access → Credential Access → Execution → Persistence → PrivEsc → Lateral → Exfil
- **DAG orchestration** — Kahn topological levels, goroutine workers, concurrency semaphore
- **82 wired dependencies** — remaining modules run as independent nodes
- **Dry-run** — print the plan without firing the full probe set
- **Profiles** — `quick` / `stealth` / `full` from YAML/TOML/JSON config

</td>
<td width="50%" valign="top">

### Coverage

- **25 platform profiles** — endpoints, capabilities, fingerprint markers
- **Chat / agents** — Open-WebUI, Dify, FastGPT, LobeChat, LibreChat, NextChat, AnythingLLM, Flowise, RagFlow, Langflow
- **Inference** — Ollama, vLLM, LocalAI, Xinference, LiteLLM
- **MLOps / UI** — Ray, MLflow, Gradio, ComfyUI, DB-GPT, Jupyter
- **Vector DBs** — ChromaDB, Qdrant, Weaviate, Milvus
- **CVE-shaped checks** — 2023–2026 IDs in probes, HTTP checks, and chains

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Protocol and payloads

- HTTP client with **redirects disabled** (cuts OAuth 302 false positives)
- WebSocket JSON-RPC helpers
- Challenge-page / SPA / LLM-refusal filters
- External YAML libraries: SSRF, injection, prompt, auth bypass, XSS, CVE-specific
- Optional payload mutation
- `--tls` for HTTPS/WSS (current client skips certificate verify — assessment-oriented)

</td>
<td width="50%" valign="top">

### Operator surface

- **`scan`** — full DAG against one host, CIDR, range, or file
- **`exploit` / `chain`** — single node or all 42 state-passing chains
- **`discover`** — TCP connect scan + platform fingerprint
- **`nuclei`** — bundled templates (45 IDs) without a Nuclei binary
- **`osint`** — Shodan / FOFA / Hunter dorks (keys from env only)
- **`mcp`** — stdio MCP server, private-range default allowlist, audit log
- Reports: JSON, dark HTML, Markdown, Mermaid

</td>
</tr>
</table>

---

## Commands

| Command | What it does |
|---------|----------------|
| `scan` | Build the DAG, run modules level-by-level, score findings |
| `exploit` | Run the DAG or a single `--chain-id` node |
| `chain` | Only the 42 multi-stage chains; a chain is “complete” when every stage hits |
| `discover` | Port scan (default AI-common ports) then fingerprint |
| `nuclei` | Execute YAML templates from `nuclei-templates/` |
| `osint` | Query cyberspace engines; never pass API keys on the CLI |
| `mcp` | Expose scan/chain/discover/nuclei/osint to an AI assistant |
| `list` | Print the 412-module catalog |
| `config` | Show merged configuration |
| `version` | Print `6.0.0` |

**Only against systems you own or are written-authorized to test.** CIDR expansion, target files, OSINT hosts, and MCP `--allow` must stay inside that writing.

```bash
# Catalog
catchclaw list

# Preview which nodes would run
catchclaw scan -t 192.168.1.10:8080 --dry-run

# Auto-fingerprint and scan
catchclaw scan -t 192.168.1.10:8080

# Force a profile
catchclaw scan -t 192.168.1.10:8080 --platform dify --profile stealth

# Reports
catchclaw scan -t 192.168.1.10:8080 -o report.json
catchclaw scan -t 192.168.1.10:8080 -o report.html --format html
catchclaw scan -t 192.168.1.10:8080 -o report.md --format markdown --severity-filter critical,high

# Batch (authorization required for every expanded address)
catchclaw scan --targets "192.168.1.0/24:8080" -o results.json
catchclaw scan -f targets.txt -o results.json

# Chains
catchclaw chain -t 192.168.1.10:8080
catchclaw exploit -t 192.168.1.10:8080 --chain-id 30

# Discovery / Nuclei / OSINT / MCP
catchclaw discover -t 192.168.1.10 --ports 3000,8080,11434
catchclaw nuclei --list
catchclaw nuclei -t http://192.168.1.10:8080
catchclaw osint --list-dorks
catchclaw osint --engine shodan --platform ollama
catchclaw mcp --allow 10.0.0.0/8
```

### `scan` flags

| Flag | Purpose |
|------|---------|
| `-t, --target` | `host:port` |
| `--targets` | Comma list, CIDR, or IP range |
| `-f, --targets-file` | One `host:port` per line |
| `--token` / `CATCHCLAW_TOKEN` | Gateway bearer token |
| `--timeout` | Seconds (default 10) |
| `-o, --output` | Report path |
| `--format` | `json` (default) · `html` · `markdown` |
| `--concurrency` | Max parallel modules (default 10) |
| `--tls` | HTTPS / WSS |
| `--callback` | Out-of-band SSRF callback URL |
| `--profile` | `quick` · `stealth` · `full` |
| `--severity-filter` | `critical,high,medium,low,info` |
| `--dry-run` | Plan only |
| `--config` | YAML / TOML / JSON |
| `--platform` | `auto` or a profile name |

OSINT keys (environment only): `SHODAN_API_KEY`, `FOFA_EMAIL` + `FOFA_KEY`, `HUNTER_API_KEY`.

---

## Platforms

Each profile carries default ports, fingerprint markers, and an endpoint map. CrewAI and LangChain exist as identifiers / CVE modules without a dedicated profile.

| Group | Platforms | Typical probes |
|-------|-----------|----------------|
| Chat / agents | Open-WebUI / OpenClaw, Dify, FastGPT, LobeChat, LibreChat, NextChat, AnythingLLM, Flowise, RagFlow, Langflow | Auth, SSRF, tenant isolation, default creds, workflow RCE |
| Gateways | LiteLLM | Default master key, spend logs, callback SSRF |
| Inference | Ollama, vLLM, LocalAI, Xinference | Unauth generate/tags, path disclosure, gallery RCE |
| MLOps / notebooks | Ray Dashboard, MLflow, Gradio, ComfyUI, DB-GPT, Jupyter | Job RCE, artifact traversal, kernel exec |
| Vector DB | ChromaDB, Qdrant, Weaviate, Milvus | Unauth collections, snapshot theft, default creds |

Fingerprint is keyword-based. Treat `discover` output as a hint and pass `--platform` when you already know the stack.

---

## Modules and DAG

`catchclaw list` loads **412** entries (counted from source in v6.0.0):

| Kind | Count | Role |
|------|------:|------|
| Handwritten exploits | 101 | Custom logic (SSRF, RCE, WS, OAuth, skill poison, CVE probes, …) |
| HTTP checks | 269 | Data-driven `path` + status + keyword (`checks.go`) |
| State-passing chains | 42 | Stage N output (`{token}`, `{role}`, …) feeds stage N+1 |
| **Registered total** | **412** | |

| Related | Count |
|---------|------:|
| Platform profiles | 25 |
| Platform identifiers | 27 |
| DAG nodes with `DependsOn` | 82 |
| Nuclei template IDs | 45 |

Handwritten catalog and chain table: **[go/README.md](go/README.md)**.

How `scan` builds the graph:

- 82 handwritten modules get explicit ATT&CK-stage edges in `go/internal/scan/scan.go`.
- HTTP checks and chains are appended as **independent** nodes (parallel with other unconstrained work).
- Execution is level-parallel under a semaphore.
- `FallbackFor` / `Condition` exist on `Node` and are not filled by the current builder.
- The attack graph records executed / skipped and can export Mermaid.

A **chain** is different: it is one module with several HTTP stages and in-memory state. It reports full compromise only when every stage succeeds.

---

## Reports, MCP, OSINT

**Reports** — JSON for pipelines; HTML (dark, chain cards) for humans; Markdown with optional Mermaid; severity filter applied before write.

**MCP** — `catchclaw mcp` speaks JSON-RPC on stdio. Tools: `catchclaw_scan`, `catchclaw_chain`, `catchclaw_discover`, `catchclaw_nuclei`, `catchclaw_list_modules`, `catchclaw_list_chains`, `catchclaw_osint`. Default allowlist is private address space; public targets need `--allow` / `--allow-file`. Every resolved IP must stay in the allowlist. Scan mutex + 2s cooldown. Keys never accepted as tool arguments.

**OSINT** — 20 built-in platform dorks. Output is host/port intelligence, not a scan. You still need authorization before you point `scan` at anything it returns.

**Nuclei** — 45 template IDs under `nuclei-templates/` (OpenClaw + `v3/` + `v4/`). The built-in runner understands HTTP word/status matchers. The Nuclei CLI can use the same directory.

---

## Install

Go **1.22+**. One static binary.

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/go
go build -o catchclaw .
```

```bash
# Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o catchclaw-linux .

# Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o catchclaw.exe .
```

Root `make build` / `make ci` delegate to `go/`. Release tags `vX.Y.Z` publish archives that include LICENSE, LEGAL.md, an SPDX SBOM, SHA-256 sums, and build provenance.

---

## Layout

```
catchclaw/
├── go/                      # v6.0.0 (supported)
│   ├── main.go
│   ├── catchclaw.example.yaml
│   └── internal/
│       ├── cli/             # scan exploit chain discover nuclei osint mcp list
│       ├── core/            # Target, Finding, DAG
│       ├── exploit/         # registry + modules + chains
│       ├── platform/        # 25 profiles
│       ├── scan/            # DAG build, CIDR, discovery
│       ├── payload/         # YAML + mutation
│       ├── nuclei/          # template runner
│       ├── osint/           # Shodan / FOFA / Hunter
│       ├── mcpserver/       # allowlist + audit
│       ├── report/          # JSON / HTML / Markdown / Mermaid
│       └── utils/           # HTTP (no redirect), WebSocket
├── payloads/                # SSRF, injection, prompt, auth, XSS, CVE
├── nuclei-templates/
├── .github/workflows/       # CI, CodeQL, release
├── LEGAL.md
├── LICENSE
└── SECURITY.md
```

---

## Development and CI

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs must keep **CI** green.

| Workflow | When | Checks |
|----------|------|--------|
| [CI](.github/workflows/ci.yml) | push / PR | `gofmt`, `go mod verify`/`tidy`, `vet`, golangci-lint, `-race` tests, coverage, host build + `list` smoke (412), cross-compile, govulncheck, Gitleaks, YAML parse, actionlint |
| [CodeQL](.github/workflows/codeql.yml) | Go changes + weekly | CodeQL on `go/` |
| [Release](.github/workflows/release.yml) | tag `vX.Y.Z` | Cross-build, LICENSE+LEGAL.md, SPDX SBOM, SHA-256, provenance attestation |

```bash
cd go && make ci
```

---

## Legal

CatchClaw sends exploit payloads, guesses credentials, and can expand one flag into many hosts. That exposure is **worldwide**. The copyright license’s choice of forum does not pick your criminal law.

Before every run, in **every** jurisdiction that may apply:

1. Hold written authorization covering hosts, time, and methods.
2. Keep CIDR / files / OSINT / MCP `--allow` inside that writing.
3. Treat reports as confidential engagement data.
4. Independently verify findings.
5. Stay non-commercial unless Coff0xc licensed you in writing.
6. Confirm the act is lawful where you are, where the target is, and anywhere in between.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND. Authors and copyright holders are not liable for claims, damages, fines, or criminal consequences arising from use in any country.

This README is not legal advice. Full text: **[LEGAL.md](LEGAL.md)**. License: **[CatchClaw Strict Non-Commercial License v2.0](LICENSE)**.

## Author

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)
