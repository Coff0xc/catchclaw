<h1 align="center">🦞 CatchClaw v6.0.0</h1>

<p align="center">
  <b>Authorized AI / LLM platform security assessment — Go implementation</b><br>
  <sub>412 registered modules (101 exploits + 269 HTTP checks + 42 chains) · 25 platform profiles · ATT&amp;CK-mapped DAG</sub>
</p>

<p align="center">
  <a href="README.md"><b>English</b></a> ·
  <a href="go/README.md">Go implementation</a> ·
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
  <img src="https://img.shields.io/badge/Version-6.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Modules-412-orange?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/Profiles-25-purple?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/License-Non--Commercial--v2.0-green?style=flat-square" alt="License">
</p>

---

> **v6.0.0** is a Go rewrite. Source of truth: [`go/`](go/). Command reference: [`go/README.md`](go/README.md). The Rust tree in `rust/` is the archived v5.x reference and is not the release target.
>
> Localized READMEs (`README_JA.md`, `README_RU.md`, `README_DE.md`, `README_FR.md`, `README_EN.md`) may lag this file. This English README is authoritative.

---

> **LEGAL RISK — READ BEFORE DOWNLOAD OR USE**
>
> CatchClaw is a **dual-use** assessment tool. **Unauthorized scanning or access is a crime** in the PRC (Criminal Law Arts. 285 / 286 and related interpretations) and under computer-misuse laws in other jurisdictions. You need **prior written authorization** for every target. You bear **all** legal, criminal, civil, and regulatory risk. The authors provide **no warranty** and **no indemnity**.
>
> **Commercial use is prohibited** without written authorization from Coff0xc (paid pentest, consulting, SaaS, resale, training commercial models, using reports as a paid deliverable).
>
> Full terms: **[LEGAL.md](LEGAL.md)** · **[LICENSE](LICENSE)** · **[SECURITY.md](SECURITY.md)**

---

## Table of contents

- [What it is](#what-it-is)
- [Module composition](#module-composition)
- [Supported platforms](#supported-platforms)
- [Installation](#installation)
- [Quick start](#quick-start)
- [CLI](#cli)
- [DAG execution](#dag-execution)
- [Nuclei templates](#nuclei-templates)
- [Project layout](#project-layout)
- [Legal risk](#legal-risk)
- [Disclaimer](#disclaimer)

---

## What it is

CatchClaw assesses **self-hosted AI / LLM infrastructure** (chat UIs, agent platforms, inference servers, vector DBs, MLOps consoles) under authorization. It maps registered modules onto MITRE ATT&CK-style phases, runs them concurrently, and writes JSON / HTML / Markdown reports plus an optional Mermaid graph.

It is an **assessment aid**. HTTP checks match status codes and body keywords. Treat hits as unverified signals until you reproduce them.

### Why teams use it (authorized engagements only)

| Job | CatchClaw |
|------|-----------|
| Breadth on AI stacks | 25 platform profiles, fingerprint + probe modules |
| Repeatable runs | DAG orchestration, `--dry-run`, profiles (`quick` / `stealth` / `full`) |
| Reporting | JSON, HTML, Markdown, Mermaid |
| CI-style templates | Nuclei YAML under `nuclei-templates/` |
| Assistant-driven scans | MCP server with private-range default allowlist |

---

## Module composition

`catchclaw list` reports **412** registered modules. Breakdown (v6.0.0, measured from source):

| Kind | Count | Where |
|------|------:|-------|
| Handwritten exploit implementations | 101 | `go/internal/exploit/modules/*.go` + `register.go` |
| Data-driven HTTP checks | 269 | `checks.go` (`path` + status + keyword) |
| Multi-stage state-passing chains | 42 | `chains.go` |
| **Registered total** | **412** | global `exploit` registry |

| Related inventory | Count |
|------|------:|
| Platform profiles (`New*Profile`) | 25 |
| Platform identifiers (`core.Platform*`, excluding unknown) | 27 |
| DAG nodes with explicit `DependsOn` | 82 |
| Nuclei template IDs | 45 |

Handwritten module catalog: [`go/README.md`](go/README.md). Full IDs: `catchclaw list`.

---

## Supported platforms

Profiles implement fingerprint markers and endpoint maps. CrewAI and LangChain appear as identifiers / CVE modules without a dedicated profile.

| Platform | Fingerprint | Probe / notes |
|------|------|------|
| OpenClaw / Open-WebUI | Auto | Built-in handwritten modules |
| Dify | Auto | `dify_probe`, `dify_tap_probe` |
| FastGPT | Auto | `fastgpt_probe` |
| NextChat | Auto | `nextchat_probe` |
| AnythingLLM | Auto | `anythingllm_probe` |
| Flowise | Auto | `flowise_probe` |
| RagFlow | Auto | `ragflow_probe` |
| LibreChat | Auto | `librechat_probe` |
| LobeChat | Auto | `lobechat_probe` |
| Langflow | Auto | `langflow_probe` |
| LiteLLM | Auto | `litellm_probe` |
| Ollama | Auto | `ollama_probe`, `ollama_probllama` |
| vLLM | Auto | `vllm_probe` |
| Ray Dashboard | Auto | `ray_probe` |
| MLflow | Auto | `mlflow_probe` |
| Gradio | Auto | `gradio_probe` |
| ComfyUI | Auto | `comfyui_probe` |
| DB-GPT | Auto | `dbgpt_probe` |
| ChromaDB | Auto | `chromadb_probe` |
| Qdrant | Auto | `qdrant_probe` |
| Weaviate | Auto | `weaviate_probe` |
| Milvus | Auto | `milvus_probe` |
| LocalAI | Auto | `localai_probe` |
| Xinference | Auto | `xinference_probe` |
| Jupyter | Auto | `jupyter_probe` |

---

## Installation

### Build from source (supported)

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/go

go build -o catchclaw .

# Windows
go build -o catchclaw.exe .
```

Requirements: **Go 1.22+**. Single static binary, no runtime deps.

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o catchclaw-linux .

# macOS
GOOS=darwin GOARCH=amd64 go build -o catchclaw-macos .
```

Root `make build` delegates to `go/`. Archived Rust v5: `make rust-build` (requires a Rust toolchain).

---

## Quick start

**Only against systems you own or are written-authorized to test.**

```bash
# Catalog
catchclaw list

# Preview DAG (no HTTP to the target besides what you already allowed)
catchclaw scan -t TARGET_IP:PORT --dry-run

# Scan (auto fingerprint)
catchclaw scan -t TARGET_IP:PORT

# Platform override
catchclaw scan -t TARGET_IP:PORT --platform dify

# Reports
catchclaw scan -t TARGET_IP:PORT -o report.json
catchclaw scan -t TARGET_IP:PORT -o report.html --format html

# Batch (still requires authorization for every address in the expansion)
catchclaw scan --targets "192.168.1.0/24:8080"
catchclaw scan -f targets.txt -o results.json

catchclaw scan -t TARGET_IP:PORT --profile stealth
catchclaw scan -t TARGET_IP:PORT --severity-filter critical,high

# Chains
catchclaw chain -t TARGET_IP:PORT
catchclaw exploit -t TARGET_IP:PORT --chain-id 30

# Discovery / templates / OSINT / MCP
catchclaw discover -t TARGET_IP
catchclaw nuclei --list
catchclaw osint --list-dorks
catchclaw mcp --allow 10.0.0.0/8
```

---

## CLI

```
CatchClaw v6.0.0 — authorized AI/LLM platform security assessment (Go)

Usage: catchclaw <COMMAND>

Commands:
  scan       Full scan (build DAG → execute → summarize)
  exploit    Run exploit modules (full DAG or --chain-id)
  chain      Multi-stage state-passing chains only
  discover   Port scan + platform fingerprint
  nuclei     Run bundled Nuclei-compatible templates
  osint      Shodan / FOFA / Hunter (keys from environment)
  mcp        MCP stdio server (default allowlist: private ranges)
  list       List registered modules
  config     Show configuration
  version    Show version
```

Flags for `scan` include `-t/--target`, `--targets`, `-f/--targets-file`, `--token`, `--timeout`, `-o/--output`, `--format json|html|markdown`, `--concurrency`, `--tls`, `--callback`, `--profile`, `--severity-filter`, `--dry-run`, `--config`, `--platform`.

Token: `--token` or `CATCHCLAW_TOKEN`. OSINT keys: `SHODAN_API_KEY`, `FOFA_EMAIL` + `FOFA_KEY`, `HUNTER_API_KEY` — never on the command line.

Current Go HTTP client: TLS certificate verification skipped; redirects disabled (avoids OAuth 302 false positives). See [SECURITY.md](SECURITY.md).

---

## DAG execution

`scan` builds a DAG from the registry:

- **82** handwritten modules have explicit ATT&CK-stage `DependsOn` edges (`go/internal/scan/scan.go`).
- Remaining registered modules (HTTP checks and chains) are attached as **independent** nodes and run when their topological level is reached (typically in parallel with other unconstrained nodes).
- Kahn level-parallel execution; semaphore caps concurrency.
- `Node` supports `FallbackFor` and `Condition`; the current builder does not populate those fields.
- Attack graph records executed / skipped and exports Mermaid.

This is **orchestration**, not 412 independently researched kill chains.

---

## Nuclei templates

`nuclei-templates/` holds **45** template IDs (OpenClaw set + `v3/` + `v4/`). `catchclaw nuclei` runs a subset of the Nuclei YAML (HTTP word/status matchers). You can also use the Nuclei CLI:

```bash
nuclei -t nuclei-templates/ -u http://TARGET_IP:PORT
```

---

## Project layout

```
catchclaw/
├── go/                         # v6.0.0 (supported)
│   ├── main.go
│   ├── go.mod
│   └── internal/
│       ├── cli/                # commands and flags
│       ├── config/
│       ├── core/               # Target, Finding, DAG
│       ├── exploit/            # registry, chains, modules
│       ├── platform/           # 25 profiles
│       ├── payload/
│       ├── nuclei/
│       ├── osint/
│       ├── mcpserver/          # allowlist + audit log
│       ├── scan/
│       ├── report/
│       └── utils/              # HTTP (no redirect), WebSocket
├── rust/                       # archived v5.x
├── payloads/                   # YAML payload libraries
├── nuclei-templates/
├── LEGAL.md                    # legal risk (binding with LICENSE)
├── LICENSE                     # Strict Non-Commercial v2.0
├── SECURITY.md
└── README.md
```

---

## Legal risk

CatchClaw can send exploit payloads, guess credentials, and expand CIDR / OSINT / MCP allowlists into many hosts. **That is the point of the tool and the source of legal exposure.**

You must, before every run:

1. Hold **written** authorization covering hosts, time, and methods.
2. Confirm CIDR expansion, target files, OSINT results, and MCP `--allow` stay inside that writing.
3. Treat reports as confidential engagement data.
4. Independently verify findings before disclosure.
5. Stay non-commercial unless Coff0xc has licensed you in writing.

Unauthorized use can be prosecuted. The copyright holder will not defend you. Details and PRC / cross-border notes: **[LEGAL.md](LEGAL.md)**.

---

## Disclaimer

This tool is for **authorized security testing** only. Test only systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND. Authors and copyright holders are not liable for claims, damages, fines, or criminal consequences arising from use.

## Author

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## License

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — commercial use prohibited without written authorization.
