# Changelog

All notable changes to this project are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The project is in alpha. While the version is `0.x`, breaking changes can happen in any release and are listed here.

The JSON result `schema_version` and the policy pack version are versioned separately from the CLI. Changes to either are called out in the entry for the release that contains them.

## [Unreleased]

Nothing yet.

## [0.1.0-alpha.1] - 2026-11-15

First alpha release. Check `docs/IMPLEMENTATION_STATUS.md` for what has been verified and what has not.

### Added

- `agentgov` command-line tool written in Go, with no cgo. Scans are read-only and offline, need no account or API key, never execute repository code, and collect no telemetry.
- `scan` command that discovers AI agents in a repository and reports which governance controls have evidence.
- Catalog of 24 governance controls in six domains, with stable control IDs and rule IDs.
- Maturity levels 0 to 4: no evidence, declared, implemented, tested, verified in operation. A static scan alone reaches level 2 at most.
- Risk profiles `baseline`, `standard`, and `high-risk`, and release decisions `ALLOW`, `BLOCK`, and `REVIEW_REQUIRED`. A high score never overrides a failed mandatory control.
- `--baseline` option for an organization baseline that repository configuration cannot weaken.
- Exit codes: `0` scan completed and policy did not fail, `1` policy failed, `2` scan or configuration error.
- Report formats: terminal, JSON, Markdown, HTML, and SARIF.
- Lexical analysis for Python, TypeScript, and JavaScript, plus JSON, YAML, TOML, Dockerfile, Compose, and CI configuration files.
- Framework awareness for LangChain and LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, PydanticAI, MCP servers and clients, and generic tool calling.
- Commands `report`, `compare`, `explain`, `controls list|show`, `policy validate|profiles`, `init`, `new`, `doctor`, and `version`.
- `evidence digest|keygen|sign|verify` commands for external evidence bound to content and signed with Ed25519.
- `serve` command for a self-hosted dashboard (beta), bound to loopback by default, with SQLite storage. PostgreSQL support is experimental.
- Opt-in upload of a scan result to a self-hosted server with `--upload-url`.
- GitHub Action (`action.yml`) that builds the CLI from source, scans a repository, and can upload SARIF and post a pull request summary.
- Example CI configurations for GitHub, GitLab, and Azure DevOps. The GitLab and Azure DevOps examples are illustrative and have not been run by the maintainers.
- Safe and deliberately vulnerable example agents.
- Community files: contributing guide, code of conduct, security policy, governance, support, and roadmap.
- Release binaries for Linux, macOS, and Windows on amd64 and arm64, with SHA-256 checksums, a Go module inventory, and build provenance. The binaries are not code-signed.

[Unreleased]: https://github.com/shahzadarain/agent-governance-auditor/compare/v0.1.0-alpha.1...main
[0.1.0-alpha.1]: https://github.com/shahzadarain/agent-governance-auditor/releases/tag/v0.1.0-alpha.1
