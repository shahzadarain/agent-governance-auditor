# Frequently asked questions

Short, honest answers. The project is in alpha. The first release is `v0.1.0-alpha.1`.

## What the tool is

### Is this a certification?

No. AgentGov Auditor reports which governance controls have evidence in your repository. It does not certify an agent, a team, or an organization. A report is input for a person who makes a decision. It is not a compliance sign-off, a legal opinion, an audit, or a penetration test.

### Is it affiliated with OWASP?

No. The project is independent. OWASP does not sponsor, approve, or endorse it. The same is true for NIST and every other body named in the documentation. The control catalog is original to this project. It maps controls to public guidance from those bodies so that you can find related reading.

### Does a passing scan mean my agent is safe?

No. A passing scan means that the controls your profile requires have evidence at the level the profile asks for. It does not mean the controls work under attack, that the agent behaves well, or that nothing was missed.

A static scan reads code. It can show that a control is declared or implemented. It cannot show that the control runs in production. Keep doing code review, testing, and security engineering.

### Does it stop my agent from doing something harmful?

No. The tool audits. It does not sit between your agent and its tools at runtime, and it does not block agent actions.

## Privacy and safety of the scan

### Does it send my code anywhere?

No. A scan is offline. It opens no network connection and collects no telemetry. Reports are written to your own machine.

Data leaves your machine only when you pass `--upload-url` to send a result to a server that you run. That upload contains the scan result (metadata, paths, line numbers, redacted summaries), not your source code. See [privacy.md](privacy.md).

### Does it run my code?

No. The scanner reads files as text. It never executes, imports, installs, or builds code from the repository it scans. This is why it is safe to run on a repository you do not trust.

### Do I need an account or an API key?

No. There is no sign-up, no license key, and no online model.

## Understanding results

### Why is my control "unknown"?

"Unknown" means the tool found no valid evidence for that control, in either direction. It is not a failure, and it is not a pass.

Common reasons:

- The control cannot be seen in source code. Examples are incident response and production monitoring. These need evidence from outside the code.
- The control exists, but in a form the detectors do not recognize yet.
- You provided evidence, but it was not valid. It may have expired, belong to a different commit, or fail a digest or signature check. The report names the reason.

What to do: run `agentgov explain <control ID>` to see what evidence the control accepts. Then add the evidence, or record an approved exception in `.agentgov.yaml`. If you believe the code clearly implements the control, please report it with the "False positive or wrong result" issue template.

### What does "declared only" mean?

It means something states that the control exists, but the tool found no implementation. For example, `.agentgov.yaml` or a README says "tool calls need human approval", and the scan finds no approval check in the code.

A declaration is maturity level 1. It is useful, because it shows intent and ownership. It is not proof. To move up, the implementation must be detectable in code (level 2), shown by test results (level 3), or shown by runtime records (level 4).

### What are the maturity levels?

| Level | Name | Meaning |
| --- | --- | --- |
| 0 | No evidence | Nothing found |
| 1 | Declared | Stated in configuration or documentation |
| 2 | Implemented | Found in code |
| 3 | Tested | Shown by test results |
| 4 | Verified in operation | Shown by runtime records |

A static scan alone reaches level 2 at most. Levels 3 and 4 need external evidence that you provide.

### Why can a 90 score still BLOCK?

Because the score and the decision answer different questions.

- The **score** summarizes overall maturity across controls. It is illustrative.
- The **decision** (`ALLOW`, `BLOCK`, or `REVIEW_REQUIRED`) comes from your policy. Each profile marks some controls as mandatory.

When one mandatory control fails, is missing, or is below the required level, the decision is `BLOCK`, whatever the score is. A high score never overrides a failed mandatory control. This is deliberate: twenty strong controls do not make up for a hardcoded production credential.

The report lists the controls that caused the decision. Fix those first.

### What do the exit codes mean?

| Exit code | Meaning |
| --- | --- |
| `0` | The scan completed and the policy did not fail |
| `1` | The policy failed |
| `2` | Scan or configuration error. This is not a policy result |

Use `--fail-on block`, `--fail-on review`, or `--fail-on never` to choose when the policy fails.

### Why did it not detect my agent?

The tool reports "no agent detected" when it cannot find one. It does not invent an agent, and it does not give an empty repository a perfect score.

Common reasons:

- **Language.** Analysis covers Python, TypeScript, and JavaScript. Agents in other languages are not detected.
- **Framework.** The tool knows LangChain and LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, PydanticAI, MCP servers and clients, and generic tool-calling patterns. A custom or less common framework may not match.
- **Analysis method.** Analysis is lexical. It is not a full parser. Dynamic imports, generated code, and unusual patterns can be missed.
- **Location.** The agent is outside the scanned folder, in an excluded path, or in a file above the size limit.

What to do: run `agentgov doctor` and check your include and exclude settings. Describe the agent in `.agentgov.yaml` as well (`agentgov init` creates a starting file), but note that in this version a declaration alone does not make the scanner assess an agent that it cannot find in code. Then please open an issue with a minimal example so that detection can improve. More checks are in [troubleshooting.md](troubleshooting.md#no-agent-was-detected).

### The scan reported something wrong. What now?

Open an issue with the "False positive or wrong result" template. Include the rule ID, the smallest snippet that reproduces the result (with secrets removed), and what you expected. Wrong results become test fixtures.

## Policy and CI

### Can a pull request weaken the policy?

Not when you use `--baseline`.

Without a baseline, the scan reads `.agentgov.yaml` from the repository, and a pull request can edit that file. With `--baseline <file>`, you pass an organization baseline from a place the pull request cannot change. Repository configuration can then make the policy stricter, but it cannot loosen the baseline.

For this to hold in CI:

- Load the baseline from a trusted location, such as a separate repository or a protected branch. Do not load it from the pull request's own files.
- Protect the CI workflow file with branch protection and required reviews. A pull request that can edit the workflow can remove the scan.

See [integrations/github/README.md](../integrations/github/README.md) for an example.

### Is it safe to run on pull requests from forks?

Yes, with the default `pull_request` trigger on GitHub. Forks get a read-only token and no secrets, which is all a read-only offline scan needs. Do not use `pull_request_target` to scan untrusted code.

### Does it work on GitLab or Azure DevOps?

The CLI runs anywhere Go builds. Example configurations are in `integrations/gitlab` and `integrations/azure-devops`. They are illustrative: the maintainers have not run them on those platforms yet.

## Installing

### Can I use it without Go?

Not yet. Today you need Go 1.27 or later:

```sh
go install github.com/shahzadarain/agent-governance-auditor/cmd/agentgov@latest
```

Or build from source:

```sh
go build -o agentgov ./cmd/agentgov
```

Release binaries with checksums are planned for the first tagged release. No release has been published yet. After a release, you will not need Go to run the tool.

On GitHub Actions you do not install anything yourself. The action builds the CLI for you.

### Which operating systems are supported?

The CLI is pure Go with no cgo. The project's CI builds and tests it on Linux, macOS, and Windows.

### Does it cost anything?

No. The project is free and open source under the Apache License 2.0. There is no paid tier.

## Project

### Who maintains it?

Shahzad Asghar ([@shahzadarain](https://github.com/shahzadarain)) is the author and currently the only maintainer. See [GOVERNANCE.md](../GOVERNANCE.md).

### How do I get help?

See [SUPPORT.md](../SUPPORT.md). For a security vulnerability, follow [SECURITY.md](../SECURITY.md) and do not open a public issue.

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md). To write a detector, read [contributing-rules.md](contributing-rules.md).
