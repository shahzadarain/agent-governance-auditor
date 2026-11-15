# Security Policy

AgentGov Auditor scans repositories that may be hostile, and its optional server can hold sensitive project metadata. We treat the tool itself as security-sensitive software.

## Supported versions

The project is in alpha (`0.1.0-dev`). No tagged release exists yet.

| Version | Supported |
| --- | --- |
| Latest commit on `main` | Yes |
| Latest tagged release, once one exists | Yes |
| Anything older | No |

Fixes land on `main` and in the next release. There are no backports during alpha.

## How to report a vulnerability

Report privately through GitHub private vulnerability reporting. This is the only reporting route.

1. Open the repository: <https://github.com/shahzadarain/agent-governance-auditor>
2. Select the **Security** tab.
3. Select **Report a vulnerability**.
4. Fill in the form and submit it.

Do not open a public issue, pull request, or discussion for a suspected vulnerability. The project has no security email address.

If the **Report a vulnerability** button is missing, open a public issue that says only "I need a private channel for a security report", with no details. A maintainer will enable the route.

## What to include

- The version or commit you tested (`agentgov version`).
- Your operating system and how you installed the tool.
- What you expected and what happened.
- Steps to reproduce. A minimal repository or file that triggers the problem helps the most.
- The impact you believe it has.
- Any fix or mitigation you can suggest.

Remove real secrets and private data from anything you send.

## What to expect

One maintainer runs this project in their own time. Please plan around that.

- Handling is best effort. There is no service-level agreement.
- The goal is to acknowledge a report within about one week. This is a goal, not a guarantee.
- You will get an honest answer on whether the report is accepted, and a rough plan when it is.
- Fix time depends on severity and complexity.
- We coordinate disclosure with you. Please give us a reasonable period to fix the problem before you publish details.
- We credit reporters in the advisory unless you ask us not to.
- The project does not pay bug bounties.

## In scope

- **The scanner on hostile input.** A crafted repository that makes `agentgov` execute code, read or write outside the scan root, follow links out of the scan root, crash, hang, or use unbounded memory or disk.
- **Report renderers.** Content from a scanned repository that injects script or markup into the HTML report, the Markdown summary, the SARIF file, or the terminal (for example through escape sequences).
- **Secret handling.** Any case where a secret value from a scanned repository appears in output, logs, or uploaded results.
- **Policy integrity.** A way for content in a pull request to weaken a baseline passed with `--baseline`, or to turn a failing decision into a passing one without an approved exception.
- **Evidence integrity.** Forged, replayed, or expired external evidence that the tool accepts as valid, or a signature check that can be bypassed.
- **The server (`agentgov serve`).** Authentication or authorization bypass, token leakage, cross-site scripting, cross-site request forgery, injection, access to another project's data, or a default configuration that listens on a non-loopback address.
- **The GitHub Action.** Shell injection through action inputs, or token exposure.
- **Supply chain.** Problems in the release workflow, checksums, or provenance.

## Out of scope

- A detector that misses an insecure pattern, or flags a safe one. These are false negatives and false positives. Report them as normal issues with the templates.
- Vulnerabilities in the deliberately vulnerable examples under `examples/` and in test fixtures. They are insecure on purpose and are never executed.
- Problems that need an attacker who already controls your machine, your CI configuration, or your server administrator account.
- A server that an operator exposed to the internet without authentication and TLS, against the documented guidance.
- Reports from automated tools with no demonstrated impact.
- Vulnerabilities in third-party dependencies with no demonstrated effect on this project. Report those upstream. Tell us if this project uses the dependency in an unsafe way.

## Security boundaries

What the tool is built to do:

- Scans are read-only and offline. The scanner reads files. It does not execute, import, or install code from the repository it scans.
- The scanner stays inside the folder you point it at and applies file size limits.
- Nothing leaves your machine unless you pass `--upload-url`. There is no telemetry.
- Results contain metadata, paths, line numbers, and redacted summaries. They are designed never to contain secret values or file contents.
- The server binds to loopback (`127.0.0.1`) by default.

What the tool does not do:

- **It audits. It does not enforce at runtime.** It reports which controls have evidence. It does not sit between your agent and its tools, and it does not stop a running agent from doing something harmful.
- **It is not a penetration test.** It does not attack your agent or your systems.
- **It is not a certification.** A passing scan is not a statement that an agent is safe, compliant, or approved by any body.
- **A static scan has limits.** Analysis is lexical, not a full parser. A static scan can show that a control is declared or implemented in code (maturity level 2 at most). It cannot show that the control works in production.
- **Unknown does not mean safe.** When the tool finds no evidence, it says so. That is not proof of a problem, and it is not proof of safety.

More detail on design assumptions belongs in `docs/threat-model.md`.

## Safe harbor for good-faith research

We welcome good-faith security research on this project. We will not pursue or support legal action against you for research that follows these rules:

- Test only installations that you own or operate, such as a copy of the CLI on your own machine or a server you started yourself.
- Do not test systems, repositories, or dashboards that belong to other people or organizations, even when they run this software.
- Do not access, change, or destroy data that is not yours.
- Do not degrade a service for others. No denial-of-service tests against shared infrastructure, including GitHub.
- Report what you find through the private route above, and give us reasonable time to fix it before you disclose it.

This statement covers this project only. It cannot authorize testing against third parties, and it does not override the terms of any platform you use.
