# Contributing to CatchClaw

Thank you for your interest in contributing.

## License and legal

By contributing you agree that your contribution is licensed under the [CatchClaw Strict Non-Commercial License v2.0](LICENSE). Commercial use is prohibited without written authorization from the copyright holder.

Read [LEGAL.md](LEGAL.md) and [SECURITY.md](SECURITY.md) before you send a patch.

- Do not contribute payloads, credentials, or target lists from real engagements.
- Do not add modules whose only purpose is to attack a named third-party production service you are not authorized to test.
- Do not file public issues that include live 0-days against third-party products; use their disclosure channel.
- Vulnerabilities **in CatchClaw** go through SECURITY.md, not a public issue.

## Primary tree

Supported implementation: **`go/`** (v6.0.0, Go 1.22+).

`rust/` is the archived v5.x tree. Do not add features there unless you are fixing a historical bug and say so in the PR.

## Development setup

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/go

go build -o catchclaw .
go vet ./...
go test ./...
gofmt -l .
```

From the repository root:

```bash
make build
make vet
make test
make fmt
```

Archived Rust checks: `make rust-test` (Rust toolchain required).

## Adding a module (Go)

1. Implement `exploit.Module` (`Meta` + `Run`) in the appropriate file under `go/internal/exploit/modules/`.
2. Register it in `register.go` (`exploit.Register(...)`) **or** add a `checkDef` / `ChainDef` if it is data-driven.
3. If the module must wait on another node, add a `DependsOn` entry in `go/internal/scan/scan.go` `chainDefs`. Unlisted modules are appended as independent DAG nodes.
4. Filter challenge pages and non-API bodies (`utils.IsChallengeResponse`, `utils.IsNonAPIResponse`).
5. Every `Finding` needs severity, evidence, and remediation.
6. Run `go vet ./...` and `go test ./...`.
7. Update `CHANGELOG.md`. If you change the registered-module count, update README numbers from source (do not invent counts).

Data-driven HTTP checks (`checks.go`) are keyword/status probes. Do not label them as confirmed RCE in `Name` unless the matcher actually proves execution.

## Code style

- Follow neighboring files. Handwritten reference: `go/internal/exploit/modules/core.go`.
- English identifiers and comments. Comments only for non-obvious constraints.
- No secrets in the tree. OSINT keys stay in the environment.
- Conventional commits:

```
feat: add langflow probe matcher for auto-login
fix: skip SPA fallback on prompt_inject
docs: correct registered module counts
test: add DAG level order test
refactor: share IMDS payload list
```

## Pull requests

- One change per PR.
- Tests for new behavior when you can exercise it without a live unauthorized target (table-driven matchers, fake HTTP).
- `go vet ./...` and `go test ./...` pass.
- `gofmt` clean.
- CHANGELOG updated for user-visible changes.
- GitHub Actions workflow **CI** is green (`go` + `govulncheck`).
- Checklist in `.github/PULL_REQUEST_TEMPLATE.md`.

## Continuous integration

Workflows live in `.github/workflows/`. Required gate for `master` is **CI**.

| Workflow | File | When | What |
|---|---|---|---|
| CI | `ci.yml` | push / PR to `master` | `gofmt -l`, `go vet`, `go test`, `go build`, `go mod verify`, `go mod tidy` diff, cross-compile, `govulncheck` |
| Rust archive | `rust-archive.yml` | changes under `rust/` only | `cargo fmt`, `cargo check --locked`, `clippy -D warnings`, `cargo test --locked` |
| Release | `release.yml` | tag `vX.Y.Z` on this repository | `CGO_ENABLED=0` cross-build, LICENSE + LEGAL.md in archives, SHA-256 sums, GitHub Release |

Local equivalent of the Go gate:

```bash
cd go
make ci
```

Do not add secrets, tokens, or engagement data to workflows or artifacts. OSINT keys stay in the operator environment. Release archives include LICENSE and LEGAL.md; keep it that way.

Dependabot: `gomod` (`/go`) weekly, `github-actions` weekly, `cargo` (`/rust`) monthly.
