# GitLab CI/CD

**Status: illustrative. This configuration has not been run on GitLab by the maintainers yet.** Test it in your own project before you rely on it. If you run it, please open an issue and tell us what worked and what did not.

[`.gitlab-ci.example.yml`](.gitlab-ci.example.yml) shows one job that installs the `agentgov` CLI, scans the repository, saves the reports, and fails the job when the release policy fails.

The scan is read-only and offline. It does not run code from your repository. It needs no account, API key, or CI/CD variable.

## How to use it

1. Copy the `agentgov` job from the example into your `.gitlab-ci.yml`.
2. Make sure the `test` stage exists in your `stages` list, or change the `stage` value.
3. Open a merge request and check the job log and artifacts.

## What the job does

1. Starts the official `golang:1.27` image. The tool needs Go 1.27 or later.
2. Installs the CLI from source:

   ```sh
   go install github.com/shahzadarain/agent-governance-auditor/cmd/agentgov@latest
   ```

3. Runs the scan:

   ```sh
   agentgov scan . --no-color \
     --json-out agentgov-out/agentgov-results.json \
     --sarif-out agentgov-out/agentgov.sarif \
     --markdown-out agentgov-out/agentgov-summary.md \
     --fail-on block
   ```

4. Saves `agentgov-out/` as job artifacts, even when the job fails.

## Exit codes

| Exit code | Meaning | Job result |
| --- | --- | --- |
| `0` | The scan completed and the policy did not fail. | Passes |
| `1` | The policy failed. | Fails |
| `2` | Scan or configuration error. This is not a policy result. | Fails |

To report without blocking the pipeline, change the flag to `--fail-on never`. To show a policy failure as a warning while a scan error still fails the job, add this to the job:

```yaml
  allow_failure:
    exit_codes: [1]
```

## Notes and limits

- **Install source.** No release exists yet, so `@latest` resolves to the newest commit on the default branch. For repeatable builds, replace `latest` with a commit SHA. Release binaries with checksums are planned for the first tagged release.
- **Network.** The install step downloads Go modules. The scan itself uses no network. On a runner with no internet access, build the binary elsewhere and provide it to the job.
- **SARIF.** The job saves a SARIF file as an artifact. GitLab security dashboards use GitLab's own report format, not SARIF. This example does not convert the file.
- **Merge request comments.** The example does not post a comment. The Markdown summary is in the artifacts.
- **Policy protection.** A merge request can edit `.agentgov.yaml`. To stop a merge request from weakening your policy, fetch a baseline profile from a project you control and pass it with `--baseline <file>`. Repository configuration cannot loosen a baseline.
- **Fork merge requests.** The scan needs no CI/CD variables, so it does not require you to expose secrets to pipelines for forks.
- **Upload.** Nothing is sent anywhere unless you add `--upload-url`. See [docs/privacy.md](../../docs/privacy.md).
