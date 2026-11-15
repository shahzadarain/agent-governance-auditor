# GitHub Action

The action runs `agentgov scan` on a repository in GitHub Actions. It writes a summary to the job page, saves the reports, and fails the job when your release policy fails.

Status: the action is exercised by this repository's own CI workflow (`.github/workflows/ci.yml`, job "GitHub Action self-test"), which scans both example agents through it and checks the outputs. See the CI badge in the [README](../README.md) for the current state. The first release tag is `v0.1.0-alpha.1`.

## Contents

- [Minimal workflow](#minimal-workflow)
- [Pin the action](#pin-the-action)
- [How the action gets the CLI](#how-the-action-gets-the-cli)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Exit codes and job status](#exit-codes-and-job-status)
- [Permissions](#permissions)
- [Pull requests from forks](#pull-requests-from-forks)
- [Baseline lock](#baseline-lock)
- [Code scanning (SARIF)](#code-scanning-sarif)
- [Pull request comment](#pull-request-comment)
- [Other CI systems](#other-ci-systems)

## Minimal workflow

Save this as `.github/workflows/agentgov.yml`. The same file is in [`examples/github-workflow/agentgov.yml`](../examples/github-workflow/agentgov.yml).

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
          path: .
          fail_on: block
```

What you get from a run:

- **Job summary.** The Markdown report appears on the workflow run page.
- **Artifact.** The JSON, SARIF, Markdown, and HTML reports, in an artifact named `agentgov-reports`.
- **Gate.** The job fails when the policy fails.

The scan is read-only and offline. It needs no account, API key, or secret.

## Pin the action

The example uses `@main` because no release tag exists yet. A branch can change under you. For real use, replace `main` with a full commit SHA that you have reviewed:

```yaml
- uses: shahzadarain/agent-governance-auditor@<full 40-character commit SHA>
```

The workflow that `agentgov init --with-workflow` writes uses `actions/checkout@v4` and this action at `@main`. Pin both lines the same way.

## How the action gets the CLI

The action is a composite action. It does not download a binary and it does not pipe a script into a shell. It does this:

1. Sets up Go with `actions/setup-go`, pinned to a commit SHA, using the Go version in this project's `go.mod`.
2. Builds `agentgov` from the action's own source at the ref you pinned. Go verifies module downloads against `go.sum`.
3. Runs the scan. Your input values reach the script through environment variables only. They are never pasted into the script text, so an input value cannot inject shell commands.

Every third-party action that the action uses is pinned to a full commit SHA.

The build adds time to each run, because the CLI is compiled on the runner. This will change when release binaries exist.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Folder to scan, relative to the workspace. |
| `profile` | empty | Risk profile: `baseline`, `standard`, or `high-risk`. Empty selects from configuration or detected capabilities. |
| `config` | empty | Path to `.agentgov.yaml`. Empty finds it in the scanned folder. |
| `baseline` | empty | Path to an organization baseline profile that the repository cannot weaken. |
| `fail_on` | `block` | Fail the job when the decision is `block`, `review` (block or review required), or `never`. |
| `upload_sarif` | `false` | Upload findings to GitHub code scanning. |
| `comment` | `false` | Post or update a summary comment on the pull request. |
| `server_url` | empty | Optional self-hosted AgentGov server to send the result to. |
| `token` | empty | Project upload token for `server_url`. Pass it from a secret. |
| `artifact_name` | `agentgov-reports` | Name of the report artifact. Empty skips the artifact. |

## Outputs

| Output | Meaning |
| --- | --- |
| `decision` | `ALLOW`, `BLOCK`, or `REVIEW_REQUIRED`. |
| `score` | Assessment maturity from 0 to 100, or `insufficient-evidence`. Illustrative only. |
| `findings` | Number of findings. |
| `exit_code` | CLI exit code: `0` passed, `1` policy failed, `2` scan error. |
| `json` | Path of the JSON result file. |
| `sarif` | Path of the SARIF file. |
| `version` | Version of the `agentgov` CLI that ran. |

Use an output in a later step by giving the action step an `id`:

```yaml
- id: agentgov
  uses: shahzadarain/agent-governance-auditor@main
  with:
    fail_on: never
- run: echo "Decision was ${{ steps.agentgov.outputs.decision }}"
```

## Exit codes and job status

The scan step itself always finishes, so that the summary and the artifact are written even when the policy fails. A last step named "Apply release policy" then sets the job result.

| CLI exit code | Meaning | Job result |
| --- | --- | --- |
| 0 | The scan completed and the policy did not fail. | Passes. |
| 1 | The policy failed. | Fails with the annotation "AgentGov policy". The summary lists the controls to fix. |
| 2 | The scan could not run, or the configuration is not valid. | Fails with the annotation "AgentGov scan error". This is not a policy result. |

To report without failing the job, set `fail_on: never`.

## Permissions

Start with read-only access and add only what a feature needs.

| Feature | Permissions |
| --- | --- |
| Scan, job summary, artifact | `contents: read` |
| `upload_sarif: "true"` | `contents: read` and `security-events: write` |
| `comment: "true"` | `contents: read` and `pull-requests: write` |

Keep `persist-credentials: false` on the checkout step. The scan does not need Git credentials.

## Pull requests from forks

With the `pull_request` trigger, GitHub gives a pull request from a fork a read-only token and no secrets. A read-only, offline scan needs nothing more, so the scan, the job summary, and the artifact work for forks.

Three features need more than a fork gets and do not work on fork pull requests: `upload_sarif`, `comment`, and upload to `server_url`.

Do not use `pull_request_target` to scan untrusted code. That trigger runs with a write token and with access to secrets. The scanner does not execute repository code, but other steps in the same job might.

## Baseline lock

A pull request can edit `.agentgov.yaml`. The configuration file can add requirements, but it can also name a weaker built-in profile. To stop a pull request from lowering your requirements, pass a baseline file that does not come from the pull request. With a baseline, the repository configuration can tighten the rules and cannot loosen them.

```yaml
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  # Check out the baseline from a repository and branch that you control.
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

`your-org/governance-baselines` and the file name are placeholders. The baseline file format is described in [policy-reference.md](policy-reference.md). Protect the workflow file itself with branch protection and required reviews, because a pull request that can edit the workflow can remove the baseline.

One limit to know: an approved `not_applicable` entry in the repository's `.agentgov.yaml` can still take a control out of scope. Review changes to that file like any other policy change. See [threat-model.md](threat-model.md#6-policy-downgrade-through-a-pull-request).

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
          upload_sarif: "true"
```

GitHub code scanning is available for public repositories and for private repositories with GitHub Code Security. On a private repository without it, GitHub refuses the upload.

The action is written so that this does not break your gate. The SARIF upload step is allowed to fail without failing the job. The scan result, the job summary, the artifact, and the release decision are not affected. The SARIF file is still in the artifact, so you can download it and open it in any SARIF viewer.

## Pull request comment

Set `comment: "true"` and grant `pull-requests: write`. The action posts the Markdown summary as a comment on the pull request. On later runs it edits its last comment and does not add a new one. The comment step is also allowed to fail without failing the job.

## Other CI systems

The action is a thin wrapper around the CLI. For GitLab and Azure DevOps, see the examples in [`integrations/gitlab`](../integrations/gitlab/README.md) and [`integrations/azure-devops`](../integrations/azure-devops/README.md). The longer GitHub notes are in [`integrations/github`](../integrations/github/README.md).
