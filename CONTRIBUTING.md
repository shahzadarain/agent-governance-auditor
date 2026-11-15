# Contributing to AgentGov Auditor

Thank you for considering a contribution. This project is early-stage (alpha, version `0.1.0-dev`). Small, focused changes with tests are the easiest to review and merge.

By taking part, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to help

- Report a bug or a false positive. Use the issue templates.
- Improve a detector, or propose a new one.
- Add a fixture that shows a real pattern the scanner misses.
- Fix or clarify documentation. Tell us where the quick start failed for you.
- Test the tool on Windows, macOS, or Linux and report what happened.

Do not report security vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).

## What you need

| Tool | Version | Needed for |
| --- | --- | --- |
| Go | 1.27 or later | Everything |
| Git | Any recent version | Everything |
| Python | 3.10 or later | Governance tests of the example agents |
| Node.js | 22 | Only when you change the dashboard in `web/` |
| Make | Optional | `make check` on macOS and Linux |

The Go code uses no cgo. You do not need a C compiler.

## Local setup

### Windows (PowerShell)

```powershell
git clone https://github.com/shahzadarain/agent-governance-auditor.git
cd agent-governance-auditor
go build -o agentgov.exe ./cmd/agentgov
.\agentgov.exe version
powershell -File scripts/check.ps1
```

### macOS and Linux

```sh
git clone https://github.com/shahzadarain/agent-governance-auditor.git
cd agent-governance-auditor
go build -o agentgov ./cmd/agentgov
./agentgov version
make check
```

If you do not have Make, run `bash scripts/check-all.sh`. It does the same work.

## The check command

Run the full check before you open a pull request. All three commands below do the same steps: format check, `go vet`, all Go tests, a build, and two smoke scans.

| System | Command |
| --- | --- |
| macOS, Linux with Make | `make check` |
| macOS, Linux, Git Bash | `bash scripts/check-all.sh` |
| Windows PowerShell | `powershell -File scripts/check.ps1` |

The smoke scans expect exit code 1 for `examples/vulnerable-agent` and exit code 0 for `examples/safe-agent`. If your change alters those results, explain why in the pull request.

Other useful commands:

```sh
go test ./...                 # all Go tests
go test ./internal/rules/...  # one package
gofmt -l .                    # list files that need formatting
go vet ./...
```

## Project layout

| Path | Purpose |
| --- | --- |
| `cmd/agentgov` | The CLI: commands, flags, exit codes |
| `internal/model` | Shared data types for agents, evidence, findings, results |
| `internal/config` | `.agentgov.yaml` types, loader, and validation |
| `internal/discovery` | Safe file walking, ignore rules, commit lookup |
| `internal/adapters` | Lexers and framework awareness for Python, TypeScript, JavaScript |
| `internal/rules` | Detectors that produce evidence and findings for controls |
| `internal/evidence` | External evidence loading, digests, signatures |
| `internal/detect` | Runs discovery, adapters, and rules together |
| `internal/controls` | Loads the 24-control catalog |
| `internal/policy`, `internal/scoring` | Status, score, and release decision |
| `internal/reporting` | Terminal, JSON, Markdown, HTML, and SARIF output |
| `internal/scanner` | Ties detection, policy, and results together |
| `internal/server`, `internal/storage` | Self-hosted dashboard server and database |
| `policies/` | Control catalog, risk profiles, JSON Schemas (embedded in the binary) |
| `web/` | Dashboard source (React, TypeScript, Vite) |
| `examples/` | Safe and vulnerable sample agents |
| `tests/fixtures/` | Small inputs for detector tests |
| `integrations/` | CI examples for GitHub, GitLab, Azure DevOps |
| `docs/` | Documentation |
| `scripts/` | Check and release scripts |

Parts of this tree are still under construction. If a path is missing, check `docs/IMPLEMENTATION_STATUS.md`.

## How to propose a change

1. **Small fix** (typo, clear bug, one detector pattern): open a pull request directly.
2. **Anything large** (new command, new detector family, new dependency, changes across packages): open an issue first. Describe the problem and your plan. Wait for a maintainer reply before you invest a lot of time.
3. **New control, changed control meaning, or any scoring or decision change**: this needs a design review. See below.

Keep each pull request to one purpose. A 100-line pull request with tests gets reviewed much faster than a 1,500-line pull request that mixes several ideas.

### Design review

Controls, maturity levels, scoring, and release decisions are the core promises of this tool. A change to any of them can alter results for every user. Before you write code:

1. Open an issue titled `Design: <short description>`.
2. State what changes, why, and which existing results would differ.
3. Show at least one example input and the result before and after.
4. Wait for agreement from a maintainer in the issue.

The review happens in the open, in the issue. See [GOVERNANCE.md](GOVERNANCE.md).

## Commit and pull request style

- Write commit subjects in the imperative mood: "Add MCP pinning detector", not "Added" or "Adds".
- Keep the subject line under 72 characters.
- Explain the reason in the body when it is not obvious.
- Branch names: `feature/<description>`, `fix/<description>`, `chore/<description>`.
- Fill in the pull request template.

## Tests are required

- Every behavior change needs a test that fails without the change.
- Detector changes need fixtures: at least one positive, one negative, and one malformed input. See [docs/contributing-rules.md](docs/contributing-rules.md).
- Tests must run offline and must not depend on the order in which they run.
- Never put a real secret, token, or private data in a fixture. Use values that are clearly fake, such as `sk-EXAMPLE-not-a-real-key`.
- Run the full check command before you push.

## Adding or changing a detector

The step-by-step guide is in [docs/contributing-rules.md](docs/contributing-rules.md). The short version:

1. Pick the control your detector supports.
2. Add the detector in `internal/rules`.
3. Register it.
4. Add positive, negative, and malformed fixtures and a table-driven test.
5. Follow the honesty rules: static analysis never claims more than "implemented", no evidence is better than a wrong claim, and secret values never appear in output.

## Dependencies

The dependency list is fixed on purpose. Do not add a Go module or an npm package without an issue and maintainer agreement first. Core scanning must work with no paid package and no cgo.

## The dashboard bundle

The built dashboard in `web/dist` is committed to the repository. This lets `go install` and `go build` embed the dashboard without Node.js.

When you change anything in `web/`:

```sh
cd web
npm ci
npm run check
npm run build
```

Commit the updated `web/dist` in the same pull request as the source change. Do not edit files in `web/dist` by hand.

## Documentation and honest status

- Update the documentation when you change behavior, flags, or output.
- If your change alters what the tool can detect or verify, update `docs/IMPLEMENTATION_STATUS.md`. State what works, what you verified, and what remains a gap.
- Do not describe a feature as working unless you ran it.

## Licensing of contributions

This project uses the Apache License 2.0. Contributions come in under the same license they go out under: by submitting a contribution, you agree to license it under Apache-2.0, as described in section 5 of the [LICENSE](LICENSE).

The project does not require a Developer Certificate of Origin sign-off or a contributor license agreement. Only submit work that you have the right to submit.

## Review expectations

One maintainer currently reviews all changes, on a best-effort basis. Reviews can take several days. A polite reminder on the pull request after a week is welcome.
