# Security Policy

## Supported versions

| Version | Status |
| ------- | ------ |
| 6.0.x   | Supported (`go/`) |
| < 6.0   | Unsupported (v5 Rust tree was removed from `master`; retrieve it from git history or tag `v5.2.0`) |

The supported product is the Go implementation in `go/`.

## Reporting a vulnerability in CatchClaw

**Do not open a public GitHub issue for security vulnerabilities in this tool.**

Report privately to the maintainer: GitHub [@Coff0xc](https://github.com/Coff0xc)

Include:

- description and impact;
- steps to reproduce;
- affected version / commit;
- suggested fix if you have one.

Do not attach live target data, customer reports, or credentials.

### Response timeline

- Acknowledgment: within 48 hours
- Initial assessment: within 7 days
- Fix for a critical issue in a supported version: within 30 days when feasible

## Scope

This policy covers **CatchClaw itself** (CLI, scan engine, MCP server, Nuclei runner, OSINT client, build and CI).

It does **not** cover vulnerabilities in platforms CatchClaw assesses (Open-WebUI, Dify, Ollama, and others). Report those to the respective maintainers.

## Product security notes (operators)

These are current behaviors, not invitations to disable controls in production scanners you run against yourself without understanding them:

- The Go HTTP client skips TLS certificate verification and does not follow redirects. That is assessment-oriented. Intercepted traffic can be MITM’d; treat reports as sensitive.
- MCP listens on stdio. Default target allowlist is private address space. Public targets require explicit `--allow` / `--allow-file`. Every resolved IP must stay in the allowlist.
- OSINT API keys are read from the environment only and must never be passed as MCP tool arguments.
- Scan modules can be intrusive (brute force, race, RCE probes). Use `--dry-run` to preview; use `--profile stealth` and a defined window on fragile systems.
- Findings can be false positives. Independent verification is required before disclosure or remediation decisions.

## Responsible use (mandatory)

CatchClaw may be used only for **authorized** security testing. Prior written authorization is required for every target.

Unauthorized scanning or access is unlawful **worldwide** wherever computer-misuse, unauthorized-access, interception, data-protection, export-control, or similar rules apply — including the law of the place you act from, the place the target and its data are located, your nationality, and any country of transit or export. The LICENSE choice of law governs copyright disputes about the license text; it does not limit any country’s criminal or regulatory law.

You assume all legal risk in every applicable jurisdiction. The authors are not liable for misuse. This file is not legal advice. Full terms: [LEGAL.md](LEGAL.md) and [LICENSE](LICENSE).
