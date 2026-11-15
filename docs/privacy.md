# Privacy

This page explains what AgentGov Auditor reads, what it writes, and what it sends. The short version:

- A scan reads files on your machine and writes reports to your machine.
- A scan uses no network and collects no telemetry.
- A scan never runs code from the repository it reads.
- Nothing is sent anywhere unless you ask for an upload with `--upload-url`.

The project is in alpha (`0.1.0-dev`). If you see behavior that differs from this page, treat it as a bug and report it. If it exposes data, report it privately as described in [SECURITY.md](../SECURITY.md).

## What the scanner reads

When you run `agentgov scan <folder>`, the scanner reads files inside that folder:

- Source files: Python, TypeScript, and JavaScript.
- Configuration files: JSON, YAML, TOML, Dockerfiles, Compose files, and CI configuration.
- `.agentgov.yaml`, when it exists.
- Evidence files that you provide, when you configure an evidence folder.
- Git metadata, to find the current commit ID.
- A baseline profile, when you pass `--baseline <file>`.

The scanner stays inside the folder you name. It applies a file size limit and skips files above it. It follows your include and exclude settings.

## What the scanner never does

- **No network.** A scan opens no network connection. It does not check for updates, download rules, or resolve packages.
- **No telemetry.** The tool collects no usage data, crash reports, or analytics. There is nothing to opt out of.
- **No code execution.** The scanner reads bytes. It does not execute, import, install, or build anything from the scanned repository.
- **No account.** A scan needs no sign-up, license key, or API key.
- **No online model.** A scan does not send code or prompts to any AI service.
- **No changes to your code.** A scan is read-only. It writes only the report files that you request. (The `init` and `new` commands create files, because that is their purpose. They are separate from `scan`.)

You can check this yourself: run a scan with the network disconnected. `agentgov doctor` also states that the network is not used.

## What the JSON result contains

The JSON result (`--format json` or `--json-out`) is the full record of a scan. The other formats (terminal, Markdown, HTML, SARIF) show the same information in other forms.

It contains:

- **Scan metadata.** Tool version, policy version, schema version, profile, time of the scan, the commit ID, and scan statistics.
- **Agents.** Name, framework, language, entry point path, declared owner and risk tier, and detected capabilities.
- **Tools and MCP connections.** Tool names and kinds, and for MCP the command name or host only.
- **Evidence.** Control ID, the detector that produced it, file path and line number, strength, validity, a short redacted summary, and stated limitations.
- **Findings.** Rule ID, severity, title, a redacted description, remediation steps, and file path and line number.
- **Assessments.** The status and maturity level of each control, the score, and the release decision with its reasons.

It is designed never to contain:

- **Secret values.** When a detector finds a hardcoded credential, the result records the kind of secret and its location, not the value. Fingerprints are not built from secret values.
- **File contents.** The result holds paths and line numbers, not copies of your source code.
- **MCP command arguments.** These can hold secrets, so the result records the command name or host only.

File locations in evidence and findings are relative to the scanned folder and use forward slashes. The result also records the scan target that you named on the command line. Check that field before you share a report if the folder path itself is sensitive.

### Things to keep in mind

The result is metadata about your project. Metadata can still be sensitive:

- File paths, agent names, tool names, and owner names can reveal internal project details.
- Finding locations show where weaknesses may exist.
- The redaction of secrets depends on detectors. This is alpha software. Review a report before you share it outside your organization.

Treat reports like any other internal security document.

## What an upload sends, and when

By default nothing is sent. An upload happens only when you pass `--upload-url <server>` to `scan`, or set `server_url` in the GitHub Action.

When you do:

- The CLI sends one HTTPS request to the server address you gave.
- The body is the same JSON result described above. No source files, prompts, or secret values are sent.
- The request carries a project upload token. The CLI reads it from an environment variable (`AGENTGOV_TOKEN` by default; change the name with `--upload-token-env`). The token does not appear on the command line.
- The CLI refuses to send the token over plain HTTP to a non-local host unless you explicitly allow it. It does not follow redirects, so the token does not travel to another host.
- The server is one that you or your organization runs. The project operates no hosted service and receives nothing.

If the upload fails, the scan result on your machine is still complete.

## What the server stores

`agentgov serve` starts a self-hosted dashboard. It listens on loopback (`127.0.0.1`) by default, so only your own machine can reach it. You control the machine, the database, and the backups.

The server stores, in SQLite by default (PostgreSQL support is experimental):

| Data | Details |
| --- | --- |
| User accounts | User name, role, and a password hash. Not the password. |
| Sessions | A hash of the session ID, with creation and expiry times. |
| Projects and members | Project names and which users belong to them. |
| Upload tokens | A hash of each token, a short prefix for identification, scopes, and usage times. Not the token itself. |
| Scans | Each uploaded JSON result in full, with its hash, the time it arrived, and the token that uploaded it. |
| Agents, findings, control results | Rows extracted from uploaded results for lists and history: names, IDs, severities, titles, paths, line numbers, statuses. |
| Audit events | Who did what and when, in a hash-chained log. |
| Settings | Server configuration values. |

The server does not store source code, because uploads do not contain it. The server sends no telemetry and does not contact the project.

Your responsibilities when you run the server:

- Keep it on loopback or a private network unless you have set up authentication and TLS. See [SECURITY.md](../SECURITY.md).
- Protect the database file and its backups. They hold every uploaded result.
- Decide how long to keep scans, and delete what you no longer need.
- If personal data laws apply to you, note that user names, owner names, and audit events are personal data that you control.

## The GitHub Action

The action runs the same scan inside your CI runner. GitHub's own services handle the files that you ask the action to publish:

- The Markdown summary goes to the job summary page.
- The reports go to a workflow artifact, unless you set `artifact_name` to empty.
- The SARIF file goes to GitHub code scanning only when you set `upload_sarif: true`.
- A pull request comment is posted only when you set `comment: true`.

The action installs Go and downloads Go modules to build the CLI. Those downloads are part of the build, not the scan.

## Installing the tool

`go install` and `go build` download Go modules from the Go module proxy and source hosts. That is standard Go tooling behavior and is separate from scanning. To avoid it, build on one machine and copy the binary.

## Questions

Open an issue if something on this page is unclear. Report a privacy defect that exposes data through the private route in [SECURITY.md](../SECURITY.md).
