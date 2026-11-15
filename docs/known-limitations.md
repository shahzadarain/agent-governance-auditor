# Known limitations

This page lists what AgentGov Auditor does not do, or does less well than you might expect. Version `0.1.0-dev` is an alpha. I would rather you read this page first than find these limits on your own.

Each item was checked against the code, the tests, or a real run before it was written here.

## What a result means

- **A result is not a certificate.** `ALLOW` means the controls that your profile requires have the evidence that the profile asks for. It does not mean the agent is safe.
- **It audits. It does not enforce.** The tool reads a repository and reports. It does not sit inside your agent and it cannot stop an action at run time.
- **It does not replace a security review or a penetration test.**
- **"Unknown" does not mean safe, and "Missing" does not always mean absent.** The scanner reports what it could see.

## How the scanner reads code

- **Analysis is lexical.** The scanner removes comments and the contents of strings and then matches patterns in the remaining code. It resolves import aliases and follows some calls. It does not build a syntax tree, track types, or follow data through a program. The original plan named a tree-sitter parser. It was not used, because it needs a C toolchain and the project ships as one static binary.
- **Many checks depend on names.** Whether a function is a kill switch, a policy check, a memory write, or an audit record is often decided by its name and the names around it. Code that does the right thing under an unusual name can be missed. Code with the right name that does the wrong thing can be credited. [CONTROL_COVERAGE.md](CONTROL_COVERAGE.md) lists the names and patterns for every control.
- **Call following is short.** From a tool, the scanner follows calls into local functions for two steps at most, and for some checks one step. A control that is enforced three calls away is not seen.
- **Some checks use small windows.** For example, the reject path of an allowlist test must come within six lines of the test.
- **Dynamic code is invisible.** Tools registered at run time, code generated at build time, and modules loaded by a computed name are not seen.
- **One weak signal is enough for some controls.** A single `timeout=` satisfies the resource limit detector. One schema validation call satisfies the guardrail detector. These detectors are optimistic.

## Languages and frameworks

- **Python, TypeScript, and JavaScript only.** Agents in other languages are not found.
- **TypeScript and JavaScript are shallower than Python.** Local imports are followed only for relative paths. Tools defined with `tool(...)` or `new DynamicStructuredTool(...)` are recorded by name, but their bodies are not inspected. Several checks are written for Python patterns only. Expect more "Unknown" and "Missing" for these languages.
- **A fixed list of frameworks.** LangGraph, LangChain, the OpenAI Agents SDK, CrewAI, AutoGen, PydanticAI, MCP, and direct tool calling with common model SDKs. See [framework-support.md](framework-support.md).
- **A declared agent is not a detected agent.** If the scanner finds no agent in code, declaring one in `.agentgov.yaml` does not produce an assessment.

## Evidence levels

- **A static scan stops at level 2.** For three controls (AGC-001, AGC-002, AGC-019) it stops at level 1. Higher levels need evidence files that you supply.
- **The scanner does not run your tests.** It reads the evidence file your test run wrote, and trusts it as far as the content binding, the expiry, and the signature allow.
- **No runtime collector is shipped.** The evidence format accepts runtime evidence, so level 4 can be reached with a file you write from your own system. There is no built-in import from OpenTelemetry or from a policy engine.
- **Evidence has no default maximum age.** An item without `valid_until` does not expire by age.
- **Unsigned evidence is credited under `baseline` and `standard`.** Only `high-risk`, or a baseline file that asks for it, requires a verified signature.

## Policy

- **The profiles are this project's defaults.** They are not an external standard. Adjust them for your organization.
- **A repository can name its own profile.** Without `--baseline`, the configuration file in the repository chooses the profile, and it may choose a weaker one than the agent's capabilities suggest. The scan prints a warning when that happens. Use a baseline file in CI to prevent it.
- **Exceptions are recorded, not verified.** An `approved_by` name in `.agentgov.yaml` is text. The scanner cannot confirm that the person approved anything. An approved "not applicable" entry satisfies a mandatory control, so review changes to that file.
- **The setting `report.redact_sensitive_data` has no effect.** Secret values are always withheld from reports, whatever the setting says.

## Files the scanner skips

- Files larger than 1 MiB by default, binary files, and archives.
- Folders such as `.git`, `node_modules`, `vendor`, `.venv`, `dist`, and `build`.
- Files that look like secret stores, such as `.env`, `*.pem`, `*.key`, and `id_rsa`. They are listed but never opened, so a secret inside one is not reported.
- `.gitignore` is not read. A file that Git ignores is still scanned unless it falls under one of the rules above.
- Scans stop at 50,000 files, 256 MiB read, or a folder depth of 40. When a limit is reached, the result says so.

## Small parsers

- **The TOML reader is minimal.** It handles what `pyproject.toml` and lockfiles use: tables, arrays of tables, strings, numbers, booleans, arrays, and inline tables. It is not a complete TOML implementation.
- **Lockfile versions** are read from `poetry.lock`, `uv.lock`, and `package-lock.json` only.
- **Git is not called.** The commit is read from the `.git` folder directly. In a Git worktree or submodule, where `.git` is a file, the commit shows as "unknown".

## What has not been verified yet

- **Operating systems.** All local test runs so far were on Windows. Linux and macOS builds compile, and the CI workflow runs the tests on all three systems once it runs on GitHub. See the CI badge in the [README](../README.md).
- **Docker and Compose.** The files in `deploy/` are written and have never been run on a Docker host.
- **PostgreSQL.** The code compiles and shares its queries with SQLite. It has never run against a PostgreSQL server. Treat it as experimental.
- **The Caddy reverse proxy example** has not been run.
- **GitLab CI and Azure Pipelines examples** are illustrative and have not been run.
- **Performance.** There are no benchmarks and no sizing numbers. The two examples scan in well under a second, which says nothing about a large repository.
- **Browsers.** The dashboard and the HTML report were checked in Chrome only. Screen readers were not tested.

## What does not exist yet

- Downloadable binaries. The release workflow exists, and no version tag has been pushed.
- Runtime evidence adapters, OpenTelemetry import, and an OPA adapter.
- An online lookup of known vulnerabilities for dependencies. Scans are offline by design.
- Mappings to standards other than the OWASP Top 10 for Agentic Applications 2026 and the NIST AI RMF functions.

## Where to look next

- Per-control limits: [CONTROL_COVERAGE.md](CONTROL_COVERAGE.md).
- Server limits: [self-hosting.md](self-hosting.md#known-gaps).
- Security assumptions and residual risks: [threat-model.md](threat-model.md).
- Current state of the project: [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

If you hit a limit that is not on this page, please open an issue. An honest list is only useful when it is complete.
