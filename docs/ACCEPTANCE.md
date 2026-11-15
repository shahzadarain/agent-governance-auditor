# Acceptance criteria

A testable definition of done. Each item names the command or test that proves
it. Current results are recorded in `docs/IMPLEMENTATION_STATUS.md`.

## Milestone 1: offline CLI

| # | Criterion | Proof |
|---|-----------|-------|
| 1.1 | The CLI builds without cgo. | `go build ./cmd/agentgov` |
| 1.2 | All 24 controls load and validate. | `go test ./internal/controls/...`, `agentgov controls list` |
| 1.3 | The vulnerable example is blocked with specific findings. | `agentgov scan examples/vulnerable-agent` exits 1 |
| 1.4 | The safe example gives a materially different, truthful result. | `agentgov scan examples/safe-agent` exits 0 |
| 1.5 | A high score cannot override a failed mandatory control. | `TestHighScoreCannotOverrideMandatoryFailure` |
| 1.6 | No agent found is not reported as a pass. | `go test ./internal/policy/... ./internal/detect/...` |
| 1.7 | Missing, failed, and unknown stay distinct. | policy status tests |
| 1.8 | Scanning never executes repository code. | hostile fixture test in `internal/detect` |
| 1.9 | Secret values never appear in any output. | redaction tests in `internal/detect` |
| 1.10 | Instructions inside a scanned repository have no effect. | README injection test in `internal/detect` |
| 1.11 | Results are deterministic for the same input. | determinism tests |
| 1.12 | Scan error (exit 2) is distinct from policy failure (exit 1). | CI smoke steps |

## Milestone 2: developer workflow

| # | Criterion | Proof |
|---|-----------|-------|
| 2.1 | `init`, `doctor`, `explain`, `controls`, `policy validate` work. | CLI tests and smoke runs |
| 2.2 | JSON output validates against the published schema. | `go test ./internal/reporting/...` |
| 2.3 | SARIF 2.1.0 output has valid structure and real locations. | `go test ./internal/reporting/...` |
| 2.4 | HTML report is self-contained and escapes hostile content. | `go test ./internal/reporting/...` |
| 2.5 | The GitHub Action runs against fixtures and sets outputs. | `action` job in `.github/workflows/ci.yml` |
| 2.6 | Binaries build for Linux, macOS, and Windows on amd64 and arm64. | `scripts/build-release.sh` |

## Milestone 3: self-hosted dashboard

| # | Criterion | Proof |
|---|-----------|-------|
| 3.1 | First-run setup uses a one-time token; there are no default credentials. | `go test ./internal/server/...` |
| 3.2 | A scan uploads with a project-scoped token and appears in the API. | server flow test; manual run recorded in status |
| 3.3 | Cross-project access is refused. | server authorization tests |
| 3.4 | The dashboard shows real API data. | browser run recorded in status |
| 3.5 | Docker Compose deployment starts on a clean Linux host. | not yet verified; requires a Docker host |

## Milestone 4: advanced assurance

| # | Criterion | Proof |
|---|-----------|-------|
| 4.1 | Levels 3 and 4 come only from bound test or runtime evidence. | policy tests; safe example evidence |
| 4.2 | Evidence signing and verification work end to end. | `go test ./internal/evidence/...` |
| 4.3 | Changed files invalidate bound evidence. | digest-mismatch tests |
