# Support

AgentGov Auditor is a free, open-source project run by one maintainer on a best-effort basis. There is no paid support and no guaranteed response time.

## Before you ask

- Run `agentgov doctor`. It checks your setup and prints what it finds.
- Read the [FAQ](docs/faq.md). It covers the most common questions, such as why a control shows as unknown.
- Run `agentgov explain <control or rule ID>` for a plain-language explanation of a result.
- Search existing issues. Someone may have reported the same thing.

## Where to ask

| You have | Go to |
| --- | --- |
| A bug | [GitHub Issues](https://github.com/shahzadarain/agent-governance-auditor/issues), "Bug report" template |
| A wrong result (false positive or missed detection) | GitHub Issues, "False positive or wrong result" template |
| A feature idea | GitHub Issues, "Feature request" template |
| An idea for a new detector | GitHub Issues, "New detector" template |
| A usage question | GitHub Discussions, if it is enabled for the repository. Otherwise open an issue. |
| A security vulnerability | Do not open an issue. Follow [SECURITY.md](SECURITY.md). |
| A Code of Conduct concern | Follow the reporting route in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). |

## What to include

Good reports get faster answers. Please include:

- The output of `agentgov version`.
- Your operating system and version, and your shell (PowerShell, bash, zsh).
- How you installed the tool (`go install`, built from source, release binary, GitHub Action).
- The exact command you ran.
- What you expected and what happened, including the exit code.
- The relevant output. Add `--no-color` so the text pastes cleanly.
- For a wrong result: the rule ID or control ID, and the smallest code snippet that reproduces it.

Remove secrets, tokens, internal host names, and private code before you post. Issues are public.

## What is out of scope

- **Private consulting.** The maintainer cannot review your private repository, design your governance program, or join calls through this project.
- **Compliance sign-off.** The project cannot confirm that your agent meets a law, a regulation, a standard, or an internal policy. The tool reports evidence. A qualified person in your organization makes that judgment.
- **Certification.** The tool does not certify anything, and the project does not issue certificates or attestations about your systems.
- **Help with attacks.** The project does not help test systems that you do not own.
- **Support for modified forks.** Please reproduce the problem on an unmodified build first.
- **Urgent response.** If you need guaranteed response times, plan for in-house ownership of the tool.

## Helping others

Answers from the community are welcome. If you solved a problem that the documentation did not cover, a short pull request to the docs helps the next person.
