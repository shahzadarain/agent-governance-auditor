# Azure Pipelines

**Status: illustrative. This configuration has not been run on Azure by the maintainers yet.** Test it in your own project before you rely on it. If you run it, please open an issue and tell us what worked and what did not.

[`azure-pipelines.example.yml`](azure-pipelines.example.yml) shows a pipeline that installs the `agentgov` CLI, scans the repository, publishes the reports, and fails the run when the release policy fails.

The scan is read-only and offline. It does not run code from your repository. It needs no account, API key, or pipeline secret.

## How to use it

1. Copy the steps from the example into your `azure-pipelines.yml`, or create a new pipeline from the example file.
2. Adjust `trigger`, `pr`, and `pool` to match your project.
3. Open a pull request and check the run summary and the `agentgov-reports` artifact.

## What the pipeline does

1. Checks out the repository without keeping credentials.
2. Installs Go with the `GoTool@0` task. The tool needs Go 1.27 or later.
3. Installs the CLI from source:

   ```sh
   go install github.com/shahzadarain/agent-governance-auditor/cmd/agentgov@latest
   ```

4. Runs the scan:

   ```sh
   agentgov scan . --no-color \
     --json-out "$OUT_DIR/agentgov-results.json" \
     --sarif-out "$OUT_DIR/agentgov.sarif" \
     --markdown-out "$OUT_DIR/agentgov-summary.md" \
     --fail-on block
   ```

5. Adds the Markdown summary to the run page.
6. Publishes the JSON, SARIF, and Markdown files as the `agentgov-reports` artifact, even when the scan step fails.

## Exit codes

| Exit code | Meaning | Step result |
| --- | --- | --- |
| `0` | The scan completed and the policy did not fail. | Succeeds |
| `1` | The policy failed. | Fails, with an error message on the run page |
| `2` | Scan or configuration error. This is not a policy result. | Fails, with an error message on the run page |

To report without failing the run, change the flag to `--fail-on never`.

## Notes and limits

- **Install source.** No release exists yet, so `@latest` resolves to the newest commit on the default branch. For repeatable builds, replace `latest` with a commit SHA. Release binaries with checksums are planned for the first tagged release.
- **Network.** The install step downloads Go modules. The scan itself uses no network.
- **Windows agents.** The example uses `ubuntu-latest` and `bash` steps. The CLI also builds on Windows, but this example has not been adapted or tested for Windows agents.
- **SARIF.** The SARIF file is in the artifact. Azure DevOps does not display SARIF without an extension. This example does not set one up.
- **Pull request comments.** The example does not post a comment. The Markdown summary is on the run page and in the artifact.
- **Policy protection.** A pull request can edit `.agentgov.yaml`. To stop a pull request from weakening your policy, check out a baseline profile from a repository you control and pass it with `--baseline <file>`. Repository configuration cannot loosen a baseline.
- **Fork pull requests.** The scan needs no secrets. Keep the setting that withholds secrets from fork builds.
- **Upload.** Nothing is sent anywhere unless you add `--upload-url`. See [docs/privacy.md](../../docs/privacy.md).
