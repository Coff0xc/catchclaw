# Changelog

All notable changes to CatchClaw will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [5.2.0] - 2026-03-24

### Added
- **7 CVE-targeted exploit modules** from 2026 threat intelligence:
  - `gateway_hijack` — CVE-2026-25253 (CVSS 8.8) gatewayURL WebSocket hijacking
  - `safebins_bypass` — CVE-2026-28363 (CVSS 9.9) GNU long-option abbreviation bypass
  - `ws_auth_brute` — CVE-2026-32025 WebSocket auth brute-force
  - `localhost_trust` — ClawJacked localhost implicit trust bypass
  - `guest_mode_abuse` — Guest Mode dangerous endpoint exposure
  - `mdns_leak` — mDNS/HTTP configuration parameter leakage
  - `skill_supply_chain` — ClawHavoc campaign malicious skill detection
- **CVE-specific payload library** — `payloads/cve_specific.yaml` with 8 targeted categories
- **4 additional CVE exploit modules** (P0):
  - `voice_ext_rce` — CVE-2026-28446 (CVSS 9.8) Voice Extension RCE
  - `env_inject` — CVE-2026-32056 environment variable injection
  - `ipv6_ssrf_bypass` — IPv4-mapped IPv6 SSRF bypass
  - `msg_platform_spoof` — Telegram/Discord/Matrix/BlueBubbles identity spoofing
- **Multi-platform security probes** (P2):
  - `librechat_probe` — LibreChat CVE-2025-69222/69220/54868
  - `lobechat_probe` — LobeChat CVE-2026-23733 Mermaid XSS→RCE
- **Enhanced payloads** (P1): IPv6 bypass, request-side injection, extension SSRF, platform-specific fingerprints
- **Platform-specific payload file** — `payloads/platform_specific.yaml` for LibreChat/LobeChat/AnythingLLM
- **Multi-target scanning** — CIDR notation (/24, /16), IP range (start-end), comma-separated targets, target file (`-f targets.txt`)
- **Port scanning & service discovery** — TCP connect scan with OpenClaw fingerprinting across common ports (80, 443, 3000, 8080, etc.)
- **Comprehensive payload library** — 5 external YAML files with 200+ payloads: SSRF (AWS/GCP/Azure/DO metadata, IP bypass, protocol smuggling), command injection, prompt injection (DAN, jailbreak, extraction), auth bypass, XSS
- **PayloadRegistry directory loading** — `from_directory()` merges all YAML files from `payloads/` folder
- **ExploitCtx payload integration** — `get_payloads(category)` helper for exploit modules to use external payloads
- **CLI `--profile`** — select scan presets from `[profile.NAME]` in catchclaw.toml (quick/stealth/full)
- **CLI `--severity-filter`** — filter results by severity (e.g., `--severity-filter critical,high`)
- **CLI `--format`** — output format selection: json, html, markdown
- **CLI `--dry-run`** — preview which exploits would execute per DAG level without scanning
- **Scan config summary box** — configuration overview displayed before scan starts
- **Improved `list` output** — numbered table with aligned columns for exploit modules
- TOML profile mechanism for scan presets (quick/full/stealth)
- HTML report generation (dark-themed, self-contained) and Markdown report output
- Release CI workflow for automated multi-platform builds (Linux/macOS/Windows)
- `rustfmt --check` and `cargo-audit` security scanning in CI pipeline
- 72 new unit tests (38 → 110 total)

### Fixed
- MinGW linker failure on paths containing CJK/bracket characters
- `log_clean()` / `log_outcome()` signature mismatch across 59 exploit modules
- `rce.rs` doc comment syntax error (`!` → `//!`)
- Missing `colored::Colorize` import in report module
- DAG test helpers updated for `(Vec<Finding>, ExploitOutcome)` tuple type
- Config serde defaults, challenge response test escaping, Unicode char count

### Changed
- Nuclei template count corrected from 45+ to 24 across all READMEs

## [5.0.0] - 2026-03-19

### Changed
- **Complete rewrite from Go to Rust** (Edition 2024, Tokio async runtime)
- CLI framework: Cobra (Go) → clap derive (Rust)
- HTTP client: net/http (Go) → reqwest with rustls-tls (Rust)
- WebSocket client: gorilla/websocket (Go) → tokio-tungstenite (Rust)
- Concurrency: goroutines (Go) → tokio::task::JoinSet + Semaphore (Rust)
- Exploit registration: manual registry (Go) → inventory crate auto-collection (Rust)

### Added
- 59 exploit modules (up from 30 in v4.0.0)
- 59-node DAG attack chain with Kahn's topological sort
- ATT&CK 9-phase mapping (Recon → Impact)
- Condition-based and fallback node execution
- AttackGraph with Mermaid diagram export
- False-positive filters: challenge page, SPA fallback, LLM refusal detection
- 38 unit tests for core modules (http, types, DAG)
- New modules: C2 exfil, skill poison, MCP inject, DNS rebind, TOCTOU race, QMD inject, keychain inject, browser upload traversal, and more

### Removed
- Go codebase (all `cmd/`, `pkg/` directories)
- Interactive shell (msfconsole-style REPL)
- Shodan/FOFA asset discovery
- AI-powered fuzzing module
- Built-in CVE database
- HTML report generation (JSON only for now) — *restored in [Unreleased]*
- MCP stdio server

## [4.0.0] - 2026-03-17

### Added
- 55 DAG attack chains
- 30 exploit modules
- Nuclei templates (23 main + 7 v3 + 15 v4)
- Interactive shell
- Shodan/FOFA discovery
- AI-powered fuzzing (Anthropic/OpenAI)

## [1.0.0] - 2026-03-15

### Added
- Initial release
- 31 attack chains, 30 exploit modules
- Go 1.22 implementation
