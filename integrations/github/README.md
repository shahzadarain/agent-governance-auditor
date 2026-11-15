# GitHub Actions

**Status:** The action is exercised by this repository's own CI workflow. The project is in alpha. The first release tag is `v0.1.0-alpha.1`.

The action scans a repository for AI agents, writes a summary to the job page, saves the reports as an artifact, and fails the job when your release policy fails.

The scan is read-only and offline. It does not run code from your repository. It needs no account, API key, or secret.

## Quick start

Copy [`workflow.example.yml`](workflow.example.yml) to `.github/workflows/agentgov.yml` in your repository. The smallest version is:

```yaml
name: AgentGov

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: shahzadarain/agent-governance-auditor@main
        with:
          fail_on: block
```

The same file is in [`examples/github-workflow/agentgov.yml`](../../examples/github-workflow/agentgov.yml).

### Pin the action

The example uses `@main` because no release tag exists yet. A branch can change. For production use, replace `main` with a full commit SHA that you have reviewed:

```yaml
- uses: shahzadarain/agent-governance-auditor@<full 40-character commit SHA>
```

The action builds the CLI from the source at the ref you pin. It does not download a binary or pipe a script into a shell.

## What you get

- **Job summary.** The Markdown report appears on the workflow run page.
- **Artifact.** JSON, SARIF, Markdown, and HTML reports, in an artifact named `agentgov-reports`.
- **Gate.** The job fails when the policy fails.
- **Optional.** Findings in GitHub code scanning, and a summary comment on the pull request.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Folder to scan, relative to the workspace. |
| `profile` | empty | Risk profile: `baseline`, `standard`, or `high-risk`. Empty selects from configuration or detected capabilities. |
| `config` | empty | Path to `.agentgov.yaml`. Empty auto-discovers it in the scanned folder. |
| `baseline` | empty | Path to an organization baseline profile that the repository cannot weaken. Check it out from a trusted location, not from the pull request. |
| `fail_on` | `block` | Fail the job when the decision is `block`, `review` (block or review required), or `never`. |
| `upload_sarif` | `false` | Upload findings to GitHub code scanning. Needs `security-events: write`. |
| `comment` | `false` | Post or update a summary comment on the pull request. Needs `pull-requests: write`. |
| `server_url` | empty | Optional self-hosted AgentGov server to send the result to. |
| `token` | empty | Project upload token for `server_url`. Pass it from a secret. |
| `artifact_name` | `agentgov-reports` | Name of the report artifact. Empty skips the upload. |

## Outputs

| Output | Meaning |
| --- | --- |
| `decision` | `ALLOW`, `BLOCK`, or `REVIEW_REQUIRED`. |
| `score` | Assessment maturity score from 0 to 100, or `insufficient-evidence`. Illustrative only. The score never changes the decision. |
| `findings` | Number of findings. |
| `exit_code` | CLI exit code: `0` passed, `1` policy failed, `2` scan error. |
| `json` | Path of the JSON result file. |
| `sarif` | Path of the SARIF file. |
| `version` | Version of the `agentgov` CLI that ran. |

## Exit codes and job status

| Exit code | Meaning | Job result |
| --- | --- | --- |
| `0` | The scan completed and the policy did not fail. | Passes |
| `1` | The policy failed. | Fails. The summary lists the controls to fix. |
| `2` | Scan or configuration error. This is not a policy result. | Fails. Check the path and the configuration. |

To report without failing the job, set `fail_on: never`.

## Permissions

Start with read-only access and add only what a feature needs.

| Feature | Permission |
| --- | --- |
| Scan, job summary, artifact | `contents: read` |
| `upload_sarif: true` | `contents: read` and `security-events: write` |
| `comment: true` | `contents: read` and `pull-requests: write` |

Set `persist-credentials: false` on the checkout step, as in the example. The scan does not need Git credentials.

## Code scanning (SARIF)

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: shahzadarain/agent-governance-auditor@main
        with:
          upload_sarif: true
```

Code scanning is available for public repositories and for private repositories with GitHub Code Security. If the upload is not possible, the step reports a warning and the job continues. The SARIF file is still in the artifact.

## Pull requests from forks

With the default `pull_request` trigger, GitHub gives a pull request from a fork a read-only token and no secrets. That is exactly what a read-only, offline scan needs. The scan, the job summary, and the artifact work for forks.

Three features need more than a fork gets, so they do not work on fork pull requests: `upload_sarif`, `comment`, and upload to `server_url`.

**Never use `pull_request_target` to scan untrusted code.** That trigger runs with a write token and with access to secrets. If such a workflow checks out the code from the pull request, a stranger's code sits next to your secrets. The scanner does not execute repository code, but other steps in the same job might. Use `pull_request`.

## Protect the policy from the pull request

A pull request can edit `.agentgov.yaml`. To stop a pull request from weakening your policy, pass a baseline that does not come from the pull request. Repository configuration can tighten the baseline but cannot loosen it.

```yaml
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  # Check out the baseline from a repository and branch that you control.
  # The workflow token must be able to read that repository.
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      repository: your-org/governance-baselines
      ref: main
      path: .baseline
      persist-credentials: false
  - uses: shahzadarain/agent-governance-auditor@main
    with:
      baseline: .baseline/agentgov-baseline.yaml
```

`your-org/governance-baselines` and the file name are placeholders. Also protect the workflow file itself with branch protection and required reviews.

## Send results to a self-hosted server

Nothing is sent anywhere unless you set `server_url`.

```yaml
- uses: shahzadarain/agent-governance-auditor@main
  with:
    server_url: https://agentgov.example.internal
    token: ${{ secrets.AGENTGOV_TOKEN }}
```

The upload sends the scan result (metadata, paths, line numbers, redacted summaries). It does not send source code. See [docs/privacy.md](../../docs/privacy.md).

## Troubleshooting

- **The job fails with exit code 2.** The scan could not run. Check that `path` exists and that `.agentgov.yaml` is valid. Run `agentgov policy validate` locally.
- **No agent detected.** The tool does not invent an agent. See [docs/faq.md](../../docs/faq.md).
- **SARIF upload warns.** Check the `security-events: write` permission and whether code scanning is available for the repository.
- **The decision is BLOCK with a high score.** A high score never overrides a failed mandatory control. The summary names the control.
