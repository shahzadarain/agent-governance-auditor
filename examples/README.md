# Examples

Four small agents that show how the scanner behaves on different code. They are fixtures. Do not deploy any of them.

The results below are real output of version `0.1.0-dev`, run from the repository root.

| Example | What it shows | Real result |
| --- | --- | --- |
| [`vulnerable-agent/`](vulnerable-agent/README.md) | A Python agent that is unsafe on purpose: a hardcoded key, SQL built from arguments, automatic approval, an unbounded loop. | `BLOCK`, 3/100, 17 findings (5 critical, 7 high, 5 medium), exit code 1 |
| [`safe-agent/`](safe-agent/README.md) | A Python agent with working controls, governance tests, and an evidence file. | `ALLOW`, 60/100, 12 controls verified by tests, 0 findings, exit code 0 |
| [`python-langgraph/`](python-langgraph/README.md) | A LangGraph agent with two framework-native controls and nothing else. | `BLOCK`, 8/100, 0 findings, exit code 1 |
| [`typescript-agent/`](typescript-agent/README.md) | A TypeScript agent with Vercel AI SDK style tools and an MCP configuration file. | `BLOCK`, 4/100, 1 medium finding, exit code 1 |
| [`github-workflow/`](github-workflow/agentgov.yml) | A workflow file to copy into your own repository. | Not a scan target |

All credentials in these folders are fake. They match the shape of real secrets so that the scanner has something to find, and they give access to nothing.

## Run them

```sh
agentgov scan examples/vulnerable-agent
agentgov scan examples/safe-agent
agentgov scan examples/python-langgraph
agentgov scan examples/typescript-agent
```

On Windows PowerShell the same commands work. If you built with `go build`, write `.\agentgov.exe` in place of `agentgov`.

## vulnerable-agent

A "finance-processing-agent" in one Python file. Its configuration file claims a low risk tier while the agent can run shell commands and issue refunds.

```text
Assessment maturity: 3/100 (illustrative only)
Coverage: 21 of 22 applicable controls have evidence
Release decision: BLOCK
```

Status counts: 10 failed, 9 missing, 2 declared only, 1 unknown, 2 not applicable.

Use it to see what findings look like, with file and line. Its README also holds a line of text that tells "AI auditors" to ignore all findings. The scan result does not change because of it. That line is a test.

## safe-agent

A "ticket-triage-agent" that uses only the Python standard library. Each control is real code, and the tests in `tests/governance/` exercise that code. `agentgov new` copies this example to create a starter agent.

```text
Assessment maturity: 60/100 (illustrative only)
Coverage: 22 of 23 applicable controls have evidence
Verified by tests: 52%   Verified in operation: 0%
Release decision: ALLOW
```

Status counts: 12 verified by tests, 7 implemented, 3 declared only, 1 unknown, 1 not applicable.

Three things to try:

```sh
agentgov scan examples/safe-agent --full
agentgov scan examples/safe-agent --profile high-risk --summary-only
agentgov evidence verify examples/safe-agent/.agentgov/evidence/governance-tests.json --root examples/safe-agent
```

The second command gives `BLOCK` at 45/100. The `high-risk` profile requires signed evidence and the example's evidence is unsigned, so the test results are credited only up to level 2.

A score of 60 is the honest number for this example. Twelve controls are proven by tests. None is proven in operation, because nothing here is deployed.

## python-langgraph

An order-support agent built with `create_react_agent`. It has `interrupt_before=["tools"]`, which the scanner credits for human approval (AGC-010), and a `recursion_limit`, which it credits for resource limits (AGC-012). Everything else is absent.

```text
Profile:  standard (inferred from the detected capabilities)
Assessment maturity: 8/100 (illustrative only)
Release decision: BLOCK
```

Status counts: 3 implemented, 14 missing, 2 unknown, 5 not applicable.

It has no `.agentgov.yaml`, so the profile is inferred and the owner control is missing. Copy the folder somewhere and run `agentgov init --yes` in the copy to see what a generated configuration looks like.

## typescript-agent

A docs-assistant agent with two tools and an `.mcp.json` file that lists two MCP servers. One server is pinned to a version and one is not.

```text
Profile:  high-risk (inferred from the detected capabilities)
Assessment maturity: 4/100 (illustrative only)
Release decision: BLOCK
```

Status counts: 2 implemented, 16 missing, 1 failed, 1 unknown, 4 not applicable. The one finding is `AGC-014.unpinned-mcp-server`.

This example also shows a limit. Analysis of TypeScript is shallower than analysis of Python, and the scanner does not look inside tools defined with `tool(...)`. See [docs/framework-support.md](../docs/framework-support.md#known-gaps).

## More

- Side-by-side pictures of the unsafe and the safe example: [docs/demo-gallery.md](../docs/demo-gallery.md).
- What each detector looks for: [docs/CONTROL_COVERAGE.md](../docs/CONTROL_COVERAGE.md).
- Small inputs used by the Go tests, including a hostile repository: [`tests/fixtures/`](../tests/fixtures/README.md).
