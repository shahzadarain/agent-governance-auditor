# CLI reference

This page lists every `agentgov` command and flag in version `0.1.0-dev`. The text comes from the tool's own `--help` output. Run `agentgov <command> --help` to see the same information for your installed version.

Commands are the same on Windows, macOS, and Linux. Where the shell syntax differs, the PowerShell form is shown first.

## Contents

- [Exit codes](#exit-codes)
- [Environment variables](#environment-variables)
- [scan](#scan)
- [report](#report)
- [compare](#compare)
- [explain](#explain)
- [controls](#controls)
- [policy](#policy)
- [evidence](#evidence)
- [init](#init)
- [new](#new)
- [doctor](#doctor)
- [serve](#serve)
- [version and completion](#version-and-completion)

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command worked. For `scan`: the scan completed and the release policy did not fail. |
| 1 | Only from `scan`: the scan completed and the release policy failed. See `--fail-on`. |
| 2 | The command could not run, or an input is not valid. This is never a policy result. |

Errors are printed as `agentgov: error: <message>`. For example:

```text
$ agentgov scan does-not-exist
agentgov: error: scan path "does-not-exist" does not exist
```

Which decisions give exit code 1 depends on `--fail-on`:

| `--fail-on` | `ALLOW` | `REVIEW REQUIRED` | `BLOCK` |
| --- | --- | --- | --- |
| `block` (default) | 0 | 0 | 1 |
| `review` | 0 | 1 | 1 |
| `never` | 0 | 0 | 0 |

To read the exit code after a command:

```powershell
agentgov scan .
$LASTEXITCODE
```

```sh
agentgov scan .
echo $?
```

## Environment variables

| Variable | Used by | Effect |
| --- | --- | --- |
| `NO_COLOR` | all commands | When set to any value, output has no color. |
| `CLICOLOR_FORCE` | all commands | When set to a value other than `0`, color is kept even if output is piped or redirected. `NO_COLOR` and `--no-color` win over it. |
| `TERM` | all commands | The value `dumb` turns color off. |
| `AGENTGOV_BASELINE` | `scan` | Default value for `--baseline`. |
| `AGENTGOV_TOKEN` | `scan` | The project upload token for `--upload-url`. Choose another variable name with `--upload-token-env`. |
| `AGENTGOV_LISTEN` | `serve` | Default for `--listen`. |
| `AGENTGOV_DATA_DIR` | `serve` | Default for `--data-dir`. |
| `AGENTGOV_DATABASE_URL` | `serve` | Default for `--database-url`. |
| `AGENTGOV_ALLOW_PUBLIC` | `serve` | Default for `--allow-public`. |
| `AGENTGOV_TRUSTED_PROXIES` | `serve` | Default for `--trusted-proxies`. |
| `AGENTGOV_MAX_UPLOAD_BYTES` | `serve` | Default for `--max-upload-bytes`. |

A flag on the command line always wins over the variable.

Setting a variable for the current terminal:

```powershell
$env:NO_COLOR = "1"
agentgov scan .
```

```sh
NO_COLOR=1 agentgov scan .
```

Color is used only for terminal output, and only when the output goes to a real terminal. Status words such as `[ok]` and `[x]` are always printed, so nothing depends on color.

## scan

```text
agentgov scan [path] [flags]
```

Scans a folder for AI agents and assesses the 24 controls. The scan is read-only and offline. It reads files and never runs them. It sends nothing anywhere unless you pass `--upload-url`. When you leave out the path, the current folder is scanned.

Common uses:

```sh
agentgov scan .
agentgov scan . --open
agentgov scan . --full
agentgov scan . --format json --output results.json
agentgov scan . --format sarif --output findings.sarif
agentgov scan . --profile high-risk --fail-on review
agentgov scan . --json-out results.json --html-out report.html --summary-only
```

### What to scan

| Flag | Default | Meaning |
| --- | --- | --- |
| `--include <patterns>` | all files | Only scan paths that match these glob patterns. |
| `--exclude <patterns>` | none | Skip paths that match these glob patterns. Folders such as `.git`, `node_modules`, and `.venv` are always skipped. |
| `--max-file-size <bytes>` | 1048576 | Skip files larger than this. |
| `--timeout <duration>` | `5m0s` | Stop the scan after this long. |
| `--config <file>` | auto | Path to `.agentgov.yaml`. By default the tool looks in the scanned folder. |

### Which rules to apply

| Flag | Default | Meaning |
| --- | --- | --- |
| `--profile <name>` | from config, else inferred | Risk profile: `baseline`, `standard`, or `high-risk`. |
| `--baseline <file>` | `AGENTGOV_BASELINE` | An organization baseline profile that the repository cannot weaken. |
| `--fail-on <when>` | `block` | Exit with code 1 when the decision is `block`, `review` (block or review), or `never`. |
| `--trust-key <file>` | none | An Ed25519 public key file used to verify signed evidence. Repeat the flag for more keys. |

When neither `--profile` nor the configuration names a profile, the tool picks one from what the agent can do. The header of the output says which profile was used and why.

### Output

| Flag | Default | Meaning |
| --- | --- | --- |
| `-f`, `--format <name>` | `terminal` | Format of the main output: `terminal`, `json`, `markdown`, `html`, or `sarif`. |
| `-o`, `--output <file>` | screen | Write the `--format` output to this file. |
| `--full` | off | Show all 24 controls in terminal output. |
| `--summary-only` | off | Print only the score, the decision, and the reasons. |
| `--open` | off | Write an HTML report to a temporary file and open it in the browser. |
| `--json-out <file>` | none | Also write a JSON result. |
| `--html-out <file>` | none | Also write a self-contained HTML report. |
| `--markdown-out <file>` | none | Also write a Markdown summary. |
| `--sarif-out <file>` | none | Also write a SARIF 2.1.0 file. |
| `--no-color` | off | Turn color off. |
| `--no-progress` | off | Do not print progress messages. |
| `-q`, `--quiet` | off | Print nothing except errors. Use with `--output` or `--fail-on`. |
| `-v`, `--verbose` | off | Print warnings and scan statistics. |

The `--*-out` flags can be combined, so one scan can write every format. When `--output` sends the main report to a file, the screen shows a two-line summary:

```text
$ agentgov scan examples/safe-agent --format json --output after.json
Wrote json report: after.json
Agents detected: 1. Assessment maturity: 60/100 (illustrative only). Release decision: ALLOW.
```

### Upload (opt-in)

| Flag | Default | Meaning |
| --- | --- | --- |
| `--upload-url <url>` | none | Send the result to a self-hosted AgentGov server. |
| `--upload-token-env <name>` | `AGENTGOV_TOKEN` | The environment variable that holds the project upload token. |
| `--upload-allow-http` | off | Allow upload over plain HTTP to a non-local host. Not recommended. |
| `--offline` | `true` | Never contact the network during the scan. Always on in this release. |

The upload sends the scan result document. It does not send source files. The token is read from the environment so that it does not appear on the command line. Plain HTTP is accepted only for a local address such as `http://127.0.0.1:8080`. For any other host the tool refuses:

```text
agentgov: error: upload failed (the scan itself completed): refusing to send the token over plain HTTP to a non-local host; use https or pass --upload-allow-http
```

Example:

```powershell
$env:AGENTGOV_TOKEN = "<project upload token>"
agentgov scan . --upload-url http://127.0.0.1:8080
```

```sh
AGENTGOV_TOKEN="<project upload token>" agentgov scan . --upload-url http://127.0.0.1:8080
```

## report

```text
agentgov report <results.json> [flags]
```

Renders a saved JSON result in another format. It does not scan again.

```sh
agentgov report results.json --format html --output report.html
agentgov report results.json --format markdown
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-f`, `--format <name>` | `terminal` | `terminal`, `json`, `markdown`, `html`, or `sarif`. |
| `-o`, `--output <file>` | screen | Write to this file. |
| `--full` | off | Show all 24 controls in terminal output. |
| `--no-color` | off | Turn color off. |

## compare

```text
agentgov compare <before.json> <after.json> [flags]
```

Shows what changed between two saved results: new findings, resolved findings, and controls whose status changed. A score trend is shown only when both scans used the same policy pack, policy version, and profile. Otherwise the comparison says why the scores cannot be compared.

```sh
agentgov scan . --format json --output before.json
agentgov scan . --format json --output after.json
agentgov compare before.json after.json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-f`, `--format <name>` | `terminal` | `terminal`, `markdown`, or `json`. |
| `-o`, `--output <file>` | screen | Write to this file. |
| `--no-color` | off | Turn color off. |

Control changes are matched per agent. Two results for agents with different IDs show findings as new or resolved but no control changes.

## explain

```text
agentgov explain <control-id>
```

Explains one control in plain language: what it is, why it exists, when it applies, what counts as proof at each level, how to fix it, and what the check cannot see. The ID can be written in full or as a number.

```sh
agentgov explain AGC-010
agentgov explain 10
```

## controls

```text
agentgov controls list
agentgov controls show <control-id> [--json]
```

`list` prints all 24 controls by domain with one plain sentence each. `show` prints the full definition of one control. With `--json` it prints the definition as JSON.

## policy

```text
agentgov policy profiles
agentgov policy validate [file]
```

`profiles` prints the three built-in risk profiles with their mandatory controls, minimum maturity, and whether signed evidence is required.

`validate` checks a `.agentgov.yaml` file. A valid file gives exit code 0:

```text
$ agentgov policy validate .agentgov.yaml
.agentgov.yaml is valid.
```

A file with problems gives exit code 2 and one line for each problem, with the field name.

## evidence

Commands for external evidence files. See [evidence.md](evidence.md) for the concepts.

```text
agentgov evidence digest <path>... [--root <dir>]
agentgov evidence keygen [--out-dir <dir>]
agentgov evidence sign <evidence.json> --key <private key file>
agentgov evidence verify <evidence.json> [--root <dir>] [--trust-key <file>]
```

| Command | What it does |
| --- | --- |
| `digest` | Prints the content digest that binds evidence to the named files. `--root` is the repository root that the paths are relative to (default `.`). |
| `keygen` | Creates an Ed25519 key pair: `agentgov-evidence.key` (private) and `agentgov-evidence.pub` (public). `--out-dir` chooses the folder (default `.`). It refuses to overwrite existing key files. |
| `sign` | Signs every item in an evidence file with the private key and rewrites the file. |
| `verify` | Checks binding, expiry, and signatures of an evidence file. `--root` is the repository root the evidence refers to. `--trust-key` can be repeated. Exit code 2 when any item has a problem. |

```sh
agentgov evidence keygen --out-dir ../keys
agentgov evidence sign .agentgov/evidence/governance-tests.json --key ../keys/agentgov-evidence.key
agentgov evidence verify .agentgov/evidence/governance-tests.json --trust-key ../keys/agentgov-evidence.pub
```

Keep the private key outside the repository, in your CI secret store.

## init

```text
agentgov init [path] [flags]
```

Creates a starter `.agentgov.yaml` for the agent in a folder. `init` looks at the folder first, so the file starts with what was detected: the agent, its tools, and a suggested risk tier. It then asks a few short questions and writes a commented file. Existing files are never overwritten unless you pass `--force`.

| Flag | Meaning |
| --- | --- |
| `-y`, `--yes` | Accept the detected defaults without asking. |
| `--profile <name>` | Risk profile to record: `baseline`, `standard`, or `high-risk`. |
| `--with-workflow` | Also write `.github/workflows/agentgov.yml`. |
| `--force` | Overwrite existing files. |

```sh
agentgov init
agentgov init --yes --with-workflow
agentgov init ./services/support-agent
```

The generated workflow refers to `actions/checkout@v4` and to this action at `@main`. Pin both to full commit SHAs before you rely on it. See [github-action.md](github-action.md#pin-the-action).

## new

```text
agentgov new <folder>
```

Creates a new folder that holds a small, working, governed agent in plain Python with no third-party packages. It includes a tool allowlist, a policy check, human approval for risky actions, a kill switch, step limits, step tracing, a tamper-evident audit log, and governance tests. The folder must not exist yet, or must be empty. Nothing is overwritten.

```sh
agentgov new my-agent
cd my-agent
python tools/run_governance_tests.py
agentgov scan .
```

The starter does not include an evidence file. Run the tests to produce one.

## doctor

```text
agentgov doctor
```

Checks that `agentgov` is set up correctly on this machine: the version, the control catalog, the risk profiles, whether the folder has a configuration file, whether the temporary folder is writable, and whether color is on. It also looks up optional tools such as Python and Docker. It only looks them up and never runs them. `doctor` sends no data anywhere.

## serve

```text
agentgov serve [flags]
```

Runs the self-hosted dashboard and the API that receives scan results. Status: beta. By default the server listens only on this machine and stores data in a local SQLite file. On first start it prints a one-time setup token. There are no default passwords.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen <address>` | `127.0.0.1:8080` | Address to listen on. |
| `--data-dir <folder>` | `agentgov-data` | Folder for the SQLite database when `--database-url` is not set. |
| `--database-url <url>` | none | A SQLite file path, or a `postgres://` URL (experimental). |
| `--allow-public` | off | Allow listening on a non-local address. Use only behind an HTTPS reverse proxy. |
| `--trusted-proxies <list>` | none | Comma-separated proxy addresses whose `X-Forwarded` headers are trusted. |
| `--max-upload-bytes <n>` | 5 MiB | Largest accepted scan upload. |
| `--trust-key <file>` | none | Ed25519 public key file for evidence verification. Repeatable. |

```sh
agentgov serve
agentgov serve --listen 127.0.0.1:9090 --data-dir ./agentgov-data
```

See [self-hosting.md](self-hosting.md) and [deployment-security.md](deployment-security.md) before you expose the server to other machines.

## version and completion

`agentgov version` prints the version, the commit and build date when known, and the policy pack:

```text
$ agentgov version
agentgov 0.1.0-dev
commit:  unknown
built:   unknown
policy:  builtin/v1
```

`agentgov completion <shell>` prints an autocompletion script for `bash`, `zsh`, `fish`, or `powershell`. Run `agentgov completion <shell> --help` for how to load it.
