# Roadmap

This roadmap lists priorities, not promises. It has no dates. Priorities change with user feedback, bug reports, and the time the maintainer has.

**Every item on this page is planned, not shipped.** No version has been released yet. The current version is `0.1.0-dev` (alpha). For what exists and has been verified today, read `docs/IMPLEMENTATION_STATUS.md`. That file is the source of truth, not this one.

## How priorities are chosen

1. Correct and honest results come first. A wrong "implemented" claim is worse than a missing feature.
2. Problems that block a first scan come next: install failures, confusing output, documentation gaps.
3. Then requests that several users report independently.
4. Then new capabilities.

To influence the roadmap, open an issue and describe your use case. Concrete examples carry more weight than votes.

## Now: alpha

Work in progress toward a usable first version. Status: planned, not shipped.

| Item | Status |
| --- | --- |
| CLI: `scan`, `report`, `compare`, `explain`, `controls`, `policy`, `init`, `new`, `doctor`, `evidence`, `version` | Planned, in development |
| Catalog of 24 governance controls with risk profiles (`baseline`, `standard`, `high-risk`) | Planned, in development |
| Reports: terminal, JSON, Markdown, HTML, SARIF | Planned, in development |
| GitHub Action that builds the CLI from source and scans a repository | Planned, in development |
| Self-hosted dashboard (`agentgov serve`), beta quality, loopback by default | Planned, in development |
| Lexical analysis for Python, TypeScript, and JavaScript, with awareness of common agent frameworks and MCP | Planned, in development |
| Documentation for a first scan on Windows, macOS, and Linux | Planned, in development |

## Next

Planned after the alpha work is stable. Status: planned, not shipped.

| Item | Status |
| --- | --- |
| First tagged release with binaries, signed checksums, and build provenance | Planned |
| More framework adapters, guided by what users report | Planned |
| Parser-backed analysis to replace or support the lexical approach, without adding cgo to the default build | Planned |
| A verified Docker and Docker Compose path for the server (the current files have not been run by the maintainers) | Planned |
| PostgreSQL verification against a real database (currently experimental) | Planned |
| GitLab and Azure DevOps examples run and verified by the maintainers | Planned |
| Lower false-positive and false-negative rates, driven by reported cases and new fixtures | Planned |

## Later

Ideas under consideration. Each one needs a design review before work starts. Status: planned, not shipped, and not committed.

| Item | Status |
| --- | --- |
| Import of OpenTelemetry data as runtime evidence | Planned, not designed |
| OIDC login for the dashboard | Planned, not designed |
| OPA/Rego adapter for policy decisions | Planned, not designed |
| Runtime evidence adapters, so controls can reach maturity levels 3 and 4 with less manual work | Planned, not designed |
| Analysis of more programming languages | Planned, not designed |

## Not planned

These are outside the project's purpose:

- A hosted, paid, or account-gated version of the baseline scan.
- Telemetry or analytics without explicit consent.
- Runtime enforcement. The tool audits; it does not block agent actions in production.
- Certification, or claims of approval by OWASP, NIST, or any other body.
- A requirement to send code to an online model in order to scan.

## Changes to this roadmap

Roadmap changes go through public pull requests. When an item ships, it moves to [CHANGELOG.md](CHANGELOG.md) and is removed from this page.
