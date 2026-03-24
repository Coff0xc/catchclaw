<h1 align="center">🦞 CatchClaw v5.3.0</h1>

<p align="center">
  <b>Multi-Plattform AI-Agent Sicherheitsbewertungstool</b><br>
  <sub>OpenClaw · Open-WebUI · LibreChat · LobeChat · Dify · FastGPT · NextChat · AnythingLLM · Flowise · RAGFlow</sub><br>
  <sub>78 DAG-Angriffsketten | 78 Exploit-Module | ATT&CK-Phasenzuordnung | Async Tokio-Engine | Angriffsgraph-Visualisierung</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md"><b>Deutsch</b></a> ·
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

> **⚠️ KOMMERZIELLE NUTZUNG STRENG VERBOTEN**
>
> Lizenziert unter **CatchClaw Strict Non-Commercial License v2.0**.
>
> **JEDE kommerzielle Nutzung ist ohne vorherige schriftliche Genehmigung des Urhebers (Coff0xc) STRENG VERBOTEN.** Verstöße werden strafrechtlich verfolgt.
>
> Verbotene Aktivitäten umfassen, sind aber nicht beschränkt auf:
> - Verkauf, Unterlizenzierung oder Vermietung der Software oder abgeleiteter Werke
> - Nutzung der Software für SaaS, Pentesting-Dienste, Beratung oder kostenpflichtige Dienste
> - Integration in kommerzielle Produkte, Plattformen oder Tools
> - Training kommerzieller AI/ML-Modelle
> - Rebranding, Umverpackung oder White-Label-Distribution
> - Jede Aktivität, die direkt oder indirekt Einnahmen generiert
>
> **Der Urheberrechtsinhaber behält sich das Recht der rückwirkenden Durchsetzung OHNE Verjährungsfrist vor, einschließlich der Rückforderung aller Gewinne, Anwaltskosten und Strafschadensersatz.**
>
> Siehe [LICENSE](LICENSE).

---

## Highlights

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CatchClaw v5.3.0                                │
├────────────────────────────────────────────────────────────────────────────┤
│  ● 78 DAG-Angriffsketten ● 78 Exploit-Module    ● Async Tokio-Engine    │
│  ● ATT&CK 9-Phasen-Map  ● Mermaid-Angriffsgraph ● JSON/HTML/MD-Berichte│
│  ● Kahn Topologische Sort. ● Semaphore-Nebenläuf. ● Bedingung/Fallback  │
│  ● Multi-Target (CIDR)  ● Port-Scan / Erkennung ● 200+ externe Payloads│
│  ● 9 Plattformen         ● Auto-Plattformerkennung ● --platform Auswahl │
├────────────────────────────────────────────────────────────────────────────┤
│  Angriffsfläche: Gateway WS API | HTTP REST | OAuth | Webhook | Node    │
│  Abdeckung: SSRF | RCE | Schlüsseldiebstahl | Session-Hijack | Privesc  │
│  Neu: C2-Exfiltration | Skill-Vergiftung | Agent-Injection | MCP | DNS  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Inhaltsverzeichnis

- [Überblick](#überblick)
- [Kernfunktionen](#kernfunktionen)
- [Unterstützte Plattformen](#unterstützte-plattformen)
- [Installation](#installation)
- [Schnellstart](#schnellstart)
- [CLI-Verwendung](#cli-verwendung)
- [78 Exploit-Module](#78-exploit-module)
- [DAG-Angriffsketten-Architektur](#dag-angriffsketten-architektur)
- [Nuclei-Vorlagen](#nuclei-vorlagen)
- [Projektstruktur](#projektstruktur)
- [Haftungsausschluss](#haftungsausschluss)

---

## Überblick

**CatchClaw** ist ein Rust-basiertes Multi-Plattform-Sicherheitsbewertungstool für AI-Agenten. Neben der primären Unterstützung für OpenClaw / Open-WebUI werden 9 Plattformen abgedeckt: LibreChat, LobeChat, Dify, FastGPT, NextChat, AnythingLLM, Flowise und RAGFlow. Es orchestriert 78 Exploit-Module durch eine DAG (Directed Acyclic Graph) Angriffskette und deckt den gesamten ATT&CK-Lebenszyklus von der Aufklärung bis zur Datenexfiltration ab.

Basierend auf der Tokio-Async-Runtime verwendet die DAG-Engine Kahns topologische Sortierung für ebenenweise parallele Ausführung mit Semaphore-begrenzter Nebenläufigkeit, bedingter Ausführung und Fallback-Knoten. Angriffsergebnisse werden als Mermaid-Flussdiagramme visualisiert.

---

## Kernfunktionen

<table>
<tr>
<td width="50%">

### Angriffs-Engine

- **78 Exploit-Module** — 10 Kategorien, automatische `inventory`-Makro-Registrierung
- **78 DAG-Angriffsketten** — 9 ATT&CK-Phasen, automatisierte Orchestrierung
- **Kahn Topologische Sortierung** — Ebenenweise parallele Ausführung mit Abhängigkeitsauflösung
- **Bedingungs-/Fallback-Knoten** — Dynamische Pfadentscheidungen basierend auf vorherigen Ergebnissen
- **Angriffsgraph-Visualisierung** — Mermaid-Export mit Treffer/Skip/Fallback-Status

</td>
<td width="50%">

### Protokollunterstützung

- **WebSocket Gateway** — Challenge-Handshake-Erkennung, JSON-RPC-Aufrufe
- **HTTP REST** — Redirect deaktiviert zur Vermeidung von OAuth 302 False Positives
- **False-Positive-Eliminierung** — Challenge-Seiten / SPA-Fallback / LLM-Verweigerung
- **TLS-Unterstützung** — rustls-Backend, `--tls` aktiviert HTTPS/WSS
- **Multi-Format-Berichte** — JSON + HTML (Darkmode) + Markdown

</td>
</tr>
<tr>
<td width="50%">

### Scan-Verbesserungen

- **Multi-Target-Scanning** — CIDR (/24), IP-Bereich, kommagetrennt, Zieldatei
- **Port-Scanning** — TCP Connect Scan + benutzerdefinierte Portbereiche
- **Multi-Plattform-Erkennung** — Automatisches Fingerprinting von 9 Plattformen (API/WebSocket/Health)
- **200+ Payloads** — SSRF/Injection/Prompt/Auth/XSS externe YAML-Bibliothek
- **Scan-Konfiguration** — TOML-Konfigurationsdatei + Profile + Proxy-Unterstützung

</td>
<td width="50%">

### CLI-Erlebnis

- **`--profile`** — Vordefinierte Scan-Konfigurationen (quick/stealth/full)
- **`--severity-filter`** — Ergebnisse nach Schweregrad filtern
- **`--format`** — Ausgabeformat: json/html/markdown
- **`--dry-run`** — DAG-Ausführungsplan anzeigen ohne Scan
- **`--targets-file`** — Batch-Zieldatei-Eingabe
- **`--platform`** — Zielplattform angeben (auto/openclaw/librechat/lobechat usw.)

</td>
</tr>
</table>

---

## Unterstützte Plattformen

| Plattform | Beschreibung | Probe-Modul |
|-----------|-------------|-------------|
| **OpenClaw** | Anthropic AI-Coding-Agent-Plattform | Integriert (alle Module) |
| **Open-WebUI** | Open-Source AI Web UI | Integriert (alle Module) |
| **LibreChat** | Multi-Provider AI-Chat-Plattform | librechat_probe |
| **LobeChat** | Open-Source AI-Chat-Framework | lobechat_probe |
| **Dify** | LLM-Anwendungsentwicklungsplattform | dify_probe |
| **FastGPT** | Wissensbasierte AI-Plattform | fastgpt_probe |
| **NextChat** | ChatGPT Web UI | nextchat_probe |
| **AnythingLLM** | All-in-One AI-Desktop-App | anythingllm_probe |
| **Flowise** | Drag & Drop LLM-Flow-Builder | flowise_probe |
| **RAGFlow** | RAG-basierte Wissens-Engine | ragflow_probe |

---

## Installation

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Release-Build (optimiert + Symbole entfernt)
cargo build --release

# Binärdatei: target/release/catchclaw
```

**Voraussetzungen:** Rust Edition 2024 (rustc 1.85+) | Windows / Linux / macOS

---

## Schnellstart

```bash
# Registrierte Module auflisten
catchclaw list

# Vollständiger Scan
catchclaw scan -t ZIEL_IP:PORT

# Scan mit JSON-Bericht
catchclaw scan -t ZIEL_IP:PORT -o report.json

# Scan mit Authentifizierungstoken
catchclaw scan -t ZIEL_IP:PORT --token "your-gateway-token"

# HTML-Bericht ausgeben
catchclaw scan -t ZIEL_IP:PORT -o report.html --format html

# Multi-Target-Scan (CIDR)
catchclaw scan --targets "192.168.1.0/24:8080"

# Batch-Scan aus Datei
catchclaw scan -f targets.txt -o results.json

# Scan-Profil verwenden
catchclaw scan -t ZIEL_IP:PORT --profile stealth

# Nur kritische/hohe Ergebnisse
catchclaw scan -t ZIEL_IP:PORT --severity-filter critical,high

# Ausführungsplan anzeigen
catchclaw scan -t ZIEL_IP:PORT --dry-run

# Zielplattform angeben
catchclaw scan -t ZIEL_IP:PORT --platform librechat

# Vollständige Angriffskette ausführen
catchclaw exploit -t ZIEL_IP:PORT --token xxx

# Einzelnen Kettenknoten ausführen
catchclaw exploit -t ZIEL_IP:PORT --chain-id 30
```

---

## CLI-Verwendung

```
CatchClaw v5.3.0 — Multi-Plattform AI-Agent Sicherheitsbewertungstool

Usage: catchclaw <COMMAND>

Commands:
  scan      Vollständiger Sicherheitsscan (DAG aufbauen → ausführen → zusammenfassen)
  exploit   Angriffsketten ausführen (vollständiger DAG oder Einzelknoten)
  list      Alle registrierten Exploit-Module auflisten
  config    Konfigurationsdatei generieren oder validieren

Scan Flags:
  -t, --target <HOST:PORT>     Zieladresse
      --targets <TARGETS>      Multi-Target (CIDR, Bereich, kommagetrennt)
  -f, --targets-file <FILE>    Zieldatei (eine pro Zeile)
      --token <TOKEN>          Gateway-Token (oder CATCHCLAW_TOKEN Umgebungsvariable)
      --timeout <SECS>         Request-Timeout in Sekunden (Standard 10)
  -o, --output <FILE>          Bericht-Ausgabepfad
      --format <FORMAT>        Ausgabeformat: json/html/markdown (Standard json)
      --profile <PROFILE>      Scan-Profil: quick/stealth/full
      --severity-filter <LVL>  Nach Schweregrad filtern (z.B. critical,high)
      --dry-run                DAG-Plan anzeigen ohne Ausführung
      --concurrency <N>        Max. parallele Worker (Standard 10)
      --tls                    HTTPS/WSS verwenden
      --callback <URL>         SSRF-Callback-URL
      --config <FILE>          TOML-Konfigurationsdatei
      --platform <PLATFORM>    Zielplattform: auto/openclaw/librechat/lobechat/dify/fastgpt/nextchat/anythingllm/flowise/ragflow (Standard auto)

Exploit Flags:
  -t, --target <HOST:PORT>     Zieladresse
      --token <TOKEN>          Gateway-Token
      --chain-id <ID>          Einzelnen Kettenknoten nach ID ausführen
      --concurrency <N>        Max. parallele Worker (Standard 10)
      --tls                    HTTPS/WSS verwenden
```

---

## 78 Exploit-Module

Nach ATT&CK-Phase und Angriffskategorie:

| Phase | Anzahl | Schlüsselmodule |
|-------|--------|----------------|
| **Recon** | 14 | cors_bypass, ws_hijack, auth_mode_abuse, log_disclosure, hidden_content, origin_wildcard, librechat_probe, lobechat_probe, dify_probe, fastgpt_probe, nextchat_probe, anythingllm_probe, flowise_probe, ragflow_probe |
| **Initial Access** | 13 | ssrf, eval_inject, prompt_inject, mcp_inject, pairing_brute, oauth_abuse, responses_exploit, ws_fuzz, acp_bypass, ssrf_rebind, ssrf_proxy_bypass, browser_request, csrf_no_origin |
| **Credential Access** | 5 | apikey_steal, oauth_token_theft, secret_extract, secrets_resolve, talk_secrets |
| **Execution** | 7 | rce, hook_inject, tools_invoke, keychain_cmd_inject, qmd_cmd_inject, exec_race_toctou, exec_socket_leak |
| **Persistence** | 8 | agent_inject, agent_file_inject, channel_inject, skill_poison, cron_bypass, session_file_write, patch_escape, link_template_inject |
| **Privilege Escalation** | 5 | approval_hijack, config_tamper, rogue_node, silent_pair_abuse, auth_disable_leak |
| **Lateral/Exfil** | 15 | session_hijack, transcript_theft, memory_data_leak, c2_exfil, browser_upload_traversal, secret_exec_abuse, bypass_soul, marker_spoof, redact_bypass, obfuscation_bypass, unicode_bypass, ratelimit_scope_bypass, flood_guard_reset, webhook_verify, skill_scanner_bypass |

---

## DAG-Angriffsketten-Architektur

```
                        ┌─────────────────────┐
                        │  Level 0 (Aufklär.)  │
                        │  CORS / WS / Auth    │
                        └─────────┬───────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │ Level 1 (Zugang)│ │ Level 1 (Cred.) │ │ Level 1 (Zugang)│
    │ SSRF / Eval /   │ │ APIKey / OAuth  │ │ Prompt / MCP /  │
    │ Pairing         │ │ Token Theft     │ │ Responses       │
    └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                   ┌─────────────────────────┐
                   │  Level 2 (Ausführung)   │
                   │  RCE / Hook / Tools     │
                   └────────────┬────────────┘
                                │
                   ┌────────────┼────────────┐
                   ▼                         ▼
         ┌─────────────────┐       ┌─────────────────┐
         │ Level 3 (Persis)│       │ Level 3 (Eskal.)│
         │ Agent / Cron    │       │ Approval / Node │
         └────────┬────────┘       └────────┬────────┘
                  └────────────┬────────────┘
                               ▼
                  ┌─────────────────────────┐
                  │  Level 4 (Exfiltr.)     │
                  │  C2 / Transcript / Leak │
                  └─────────────────────────┘
```

**Ausführungsmerkmale:** Kahn Topologische Sortierung → Ebenenweiser Parallelismus | Semaphore-Nebenläufigkeit | `depends_on` Abhängigkeiten | `fallback_for` Fallback | `condition` Bedingte Ausführung | `AttackGraph` Mermaid-Export

---

## Nuclei-Vorlagen

`nuclei-templates/` enthält 24 eigenständige Nuclei-kompatible YAML-Vorlagen:

```bash
nuclei -t nuclei-templates/ -u http://ZIEL:PORT
nuclei -t nuclei-templates/ -l targets.txt
nuclei -t nuclei-templates/ -u http://ZIEL:PORT -severity critical
```

---

## Projektstruktur

```
catchclaw/
├── rust/
│   ├── Cargo.toml                 # Projektkonfiguration
│   └── src/
│       ├── main.rs                # CLI-Einstiegspunkt (clap derive)
│       ├── config/mod.rs          # AppConfig + Profile + Protokollkonstanten
│       ├── chain/
│       │   ├── dag.rs             # DAG-Engine (Toposort + Nebenläuf. + AttackGraph)
│       │   └── chains.rs          # 78 Angriffsketten-Knotendefinitionen
│       ├── exploit/
│       │   ├── registry.rs        # ExploitMeta + inventory-Registrierungssystem
│       │   ├── base.rs            # ExploitCtx gemeinsamer Kontext
│       │   └── *.rs               # 78 Exploit-Modul-Implementierungen
│       ├── platform/              # Multi-Plattform-Probe-Module
│       │   ├── mod.rs             # Plattformerkennung und -routing
│       │   ├── librechat.rs       # LibreChat-Probe
│       │   ├── lobechat.rs        # LobeChat-Probe
│       │   ├── dify.rs            # Dify-Probe
│       │   ├── fastgpt.rs         # FastGPT-Probe
│       │   ├── nextchat.rs        # NextChat-Probe
│       │   ├── anythingllm.rs     # AnythingLLM-Probe
│       │   ├── flowise.rs         # Flowise-Probe
│       │   └── ragflow.rs         # RAGFlow-Probe
│       ├── scan/mod.rs            # Vollständiger Scan + Multi-Target
│       ├── report/mod.rs          # JSON/HTML/Markdown-Berichte
│       └── utils/
│           ├── types.rs           # Target / Finding / Severity / ScanResult
│           ├── http.rs            # HTTP-Client + False-Positive-Filter
│           ├── ws.rs              # GatewayWsClient (WS + Challenge-Erkennung)
│           ├── target_parser.rs   # Multi-Target-Parsing
│           ├── port_scan.rs       # Port-Scanning + Service-Erkennung
│           ├── payload_registry.rs # PayloadRegistry (YAML-Laden + Verzeichnismerge)
│           └── payload_mutator.rs # Payload-Mutationsengine
├── payloads/                      # 200+ externe Payloads (YAML)
│   ├── ssrf/                      # SSRF: AWS/GCP/Azure/IP-Bypass
│   ├── command_injection/         # Befehlsinjektion/Shell-Metazeichen
│   ├── prompt_injection/          # Prompt-Injektion/Jailbreak
│   ├── auth/                      # Token/Header/Pfad-Traversierung
│   └── xss/                       # XSS: reflektiert/Event/Filter-Bypass
├── nuclei-templates/              # 24 Nuclei YAML-Vorlagen
├── scripts/gen_dag_chains.py      # DAG-Ketten-Generierungshilfe
└── LICENSE                        # CatchClaw Strict Non-Commercial License v2.0
```

---

## Haftungsausschluss

Dieses Tool ist ausschließlich für **autorisierte Sicherheitstests** bestimmt. Testen Sie nur Systeme, die Sie besitzen oder für deren Test Sie eine ausdrückliche schriftliche Genehmigung haben. Unbefugter Zugriff auf Computersysteme ist illegal. Der Autor übernimmt keine Verantwortung für jeglichen Missbrauch.

## Autor

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## Lizenz

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — Kommerzielle Nutzung streng verboten.
