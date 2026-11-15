# Implementation status

Last updated: 2026-11-15. Version: `0.1.0-alpha.1` (alpha). Builds from `main` report `0.1.0-dev`.

This file records what works, how it was verified, and what is not done. A
feature is listed as working only when a command or test in this file proves
it.

## Summary

| Milestone | State |
|-----------|-------|
| 1. Offline CLI, 24 controls, scoring, release decision | Working, tested |
| 2. Reports, onboarding commands, GitHub Action, release scripts | Working, tested. CI passes on Linux, macOS, and Windows runners, including the action self-test |
| 3. Self-hosted API and dashboard | Beta. SQLite path tested. Docker, Compose, Caddy, and PostgreSQL files ship unverified |
| 4. Tested and signed evidence | Working for file-based test evidence. Runtime adapters and OpenTelemetry import are not built |

## Verified commands

All commands below were run on Windows Server 2022 (amd64) with Go 1.27.4.
The CI workflow repeats the build, the tests, and the smoke scans on
`ubuntu-latest`, `macos-latest`, and `windows-latest`, and passed on all three
on 2026-11-15.

| Command | Result |
|---------|--------|
| `go build ./...`, `go vet ./...`, `gofmt -l .` | Clean |
| `go test ./... -count=1` | 710 passed, 0 failed, 1 skipped (a development aid) across 14 packages |
| `GOOS=linux go build`, `GOOS=darwin GOARCH=arm64 go build`, `GOOS=linux GOARCH=arm64 go vet ./...` | Cross-compiles without cgo |
| `agentgov scan examples/vulnerable-agent` | BLOCK, exit 1, 3/100, 17 findings (5 critical, 7 high, 5 medium) |
| `agentgov scan examples/safe-agent` | ALLOW, exit 0, 60/100, 12 controls verified by tests, 0 findings |
| `agentgov scan examples/safe-agent --profile high-risk` | BLOCK, exit 1, 45/100: unsigned test evidence is capped, and three mandatory controls are below the required level |
| `agentgov scan tests/fixtures/no-agent` | REVIEW_REQUIRED, exit 0, no score |
| `agentgov scan does-not-exist` | Exit 2 |
| `python tools/run_governance_tests.py` in the safe example | 56 tests passed; wrote 12 evidence items bound to file content |
| `agentgov new`, then the test runner, then `scan` in a fresh folder | ALLOW, 60/100 |
| `agentgov evidence keygen`, `sign`, `verify --trust-key` | 12 items valid, integrity verified |
| `agentgov init --yes`, `policy validate`, `explain`, `controls list`, `doctor`, `report`, `compare` | Work as documented |
| `agentgov serve`, `/healthz`, `/api/v1/version`, embedded dashboard | Served from the single binary on 127.0.0.1 |
| Dashboard `npm run check`, `npm run build`, `npm audit --omit=dev` | 26 unit tests passed; build clean; 0 vulnerabilities |
| Dashboard end-to-end, Chrome headless, against the real server | 15 of 15 passed, no CSP violations |
| GitHub Action self-test (`action` job in CI) | Vulnerable example: BLOCK with findings. Safe example: not blocked. Outputs and artifacts produced |
| Security workflow | `govulncheck` and `npm audit` passed |

Test counts by package: cmd/agentgov 20, adapters 24, config 68, controls 31,
detect 19, discovery 26, evidence 33, policy 117, reporting 76, rules 209,
scoring 26, server 46, storage 12, policies 3.

## What the tests prove

- A high score cannot override a failed mandatory control
  (`TestHighScoreCannotOverrideMandatoryFailure`,
  `TestHighScoreStillBlocksUnderHighRiskProfile`).
- Missing, failed, unknown, and error stay distinct, and a collector error
  never passes.
- A repository configuration can tighten the policy and cannot weaken it. An
  organization baseline supplied outside the repository wins.
- Scanning does not execute repository code (hostile fixture) and does not
  modify the target.
- Secret values do not appear in terminal, JSON, SARIF, HTML, or Markdown
  output.
- Instruction text inside a scanned repository has no effect on the result.
- Reports escape hostile content: HTML, Markdown, terminal control
  characters.
- JSON output validates against `policies/schema/scan-result.schema.json`,
  and the schema is checked against the Go model for drift.
- Evidence that is expired, bound to other content, unbound, or badly signed
  earns no credit, and the reason is reported.
- Server: one-time bootstrap token, no default credentials, hashed project
  tokens, CSRF checks, cross-project access refused, upload validation,
  tamper-evident audit chain.

## Known gaps

Detection

- Analysis is lexical, through purpose-built lexers in pure Go. It is not a
  full parser. Several checks depend on naming. See
  `docs/known-limitations.md`.
- JavaScript and TypeScript coverage is shallower than Python.
- A static scan supports maturity level 2 at most. Levels 3 and 4 need
  evidence files.
- Deviation from the original specification: tree-sitter was not used,
  because it requires cgo.

Not verified

- Docker image, both Compose files, and the Caddy example: written, never
  run. No Docker host was available.
- PostgreSQL: compiles and shares the SQLite query layer; never run against
  a database. Treat it as experimental.
- GitLab CI and Azure Pipelines examples: illustrative, never run.
- No performance benchmarks exist. No sizing numbers are published.
- The dashboard was tested in Chrome only. Screen readers and other browsers
  were not tested.

Not built

- Runtime evidence adapters, OpenTelemetry import, OPA/Rego adapter, OIDC
  login, the optional LLM reviewer.
- Server endpoints for password change, account disable, project deletion,
  and retention.
- Standards mappings cover the OWASP Top 10 for Agentic Applications 2026
  identifiers and NIST AI RMF 1.0 functions only. AISVS and MITRE ATLAS are
  not mapped. AGC-003, AGC-022, and AGC-023 have no mapping.

## Next action

1. Verify the Docker Compose deployment on a Linux host.
2. Code-sign the Windows and macOS binaries.
