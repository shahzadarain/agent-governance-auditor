# Control coverage matrix

This page states, control by control, what the static detectors recognize and where they stop. It is built from the detector code in `internal/rules`, the tests next to it, and real scans of the two example agents with version `0.1.0-dev`.

Read it before you trust a result. A detector that recognizes five patterns will miss the sixth.

## How to read this page

- **Rule IDs** are the names that findings carry in reports and in SARIF.
- **Counts as implemented** lists the signals that raise a control to "Implemented (not yet tested)".
- **Reported as a failure** lists the patterns that produce a finding and the status "Failed".
- **Static maximum** is the highest maturity a scan can give without evidence files. It is 2 for most controls and 1 for three of them.
- **Safe example** is the real status of `examples/safe-agent`. "Tested" means the example's own test run supplied evidence that lifted the control to level 3.
- **Unit test** names the Go test in `internal/rules/rules_test.go` that exercises the detector with small positive and negative cases.

Three rules hold for every control:

1. Static evidence never goes above the static maximum. The tests `TestStaticEvidenceIsCapped` and `TestStaticEvidenceNeverExceedsImplementation` check this.
2. "Missing" is reported only when the scanner looked in the right place and found nothing. When it cannot tell, the status is "Unknown".
3. Every detector reads code as text with comments and string contents removed. None of them runs anything.

## Summary

Statuses are from `agentgov scan examples/vulnerable-agent` and `agentgov scan examples/safe-agent`.

| Control | Static max | Vulnerable example | Safe example | Tested evidence in safe example | Unit test |
| --- | --- | --- | --- | --- | --- |
| AGC-001 Owner and Inventory | 1 | Declared only | Declared only | No | Yes |
| AGC-002 Dynamic Risk Tiering | 1 | Failed | Declared only | No | Yes |
| AGC-003 Integrated Change Control | 2 | Missing | Implemented | No | Yes |
| AGC-004 Dedicated Non-Human Identity | 2 | Failed | Implemented | No | Yes |
| AGC-005 Allowlisted Tool Access | 2 | Failed | Verified by tests | Yes | Yes |
| AGC-006 Short-Lived Scoped Tokens | 2 | Unknown | Unknown | No | Yes |
| AGC-007 User-Enforced Data Layer | 2 | Failed | Verified by tests | Yes | Yes |
| AGC-008 Vault-Injected Secrets | 2 | Failed | Implemented | No | Yes |
| AGC-009 External Policy Engine | 2 | Missing | Verified by tests | Yes | Yes |
| AGC-010 Human Approval Gates | 2 | Failed | Verified by tests | Yes | Yes |
| AGC-011 Dual Content Guardrails | 2 | Missing | Verified by tests | Yes | Yes |
| AGC-012 Multi-Level Resource Limits | 2 | Failed | Verified by tests | Yes | Yes |
| AGC-013 Disposable Sandbox Environments | 2 | Failed | Implemented | No | Yes |
| AGC-014 Vetted Tool Supply Chain | 2 | Failed | Implemented | No | Yes |
| AGC-015 Context Memory Integrity | 2 | Not applicable | Verified by tests | Yes | Yes |
| AGC-016 Authenticated Inter-Agent Messages | 2 | Not applicable | Not applicable | No | Yes |
| AGC-017 Instant Agent Kill Switch | 2 | Declared only | Verified by tests | Yes | Yes |
| AGC-018 Reversible Action Design | 2 | Missing | Verified by tests | Yes | Yes |
| AGC-019 Dedicated Incident Runbook | 1 | Missing | Declared only | No | Yes |
| AGC-020 Mandatory Regression Evals | 2 | Missing | Verified by tests | Yes | Yes |
| AGC-021 Continuous Red Teaming | 2 | Missing | Implemented | No | Yes |
| AGC-022 Complete Step Tracing | 2 | Failed | Verified by tests | Yes | Yes |
| AGC-023 Tamper-Evident Audit Trail | 2 | Missing | Verified by tests | Yes | Yes |
| AGC-024 Real-Time Operational Monitoring | 2 | Missing | Implemented | No | Yes |

Totals for the safe example: 12 verified by tests, 7 implemented, 3 declared only, 1 unknown, 1 not applicable. No control in either example reaches level 4, because the project ships no runtime collector.

Neither example exercises AGC-016, and neither produces evidence for AGC-006. Those two detectors are covered by unit tests only.

## Domain A: Accountability

### AGC-001 Owner and Inventory

- **Rule IDs:** `AGC-001.incomplete-declaration`, `AGC-001.undeclared-tool`.
- **Counts as declared:** an agent entry in `.agentgov.yaml` with an ID, an owner, a purpose or description, and a risk tier.
- **Reported as a finding:** a declaration with a field missing; a tool found in code that `capabilities.declared_tools` does not list.
- **Static maximum:** 1. The scanner can see that a file names an owner. It cannot see that the owner exists or agreed.
- **Unit test:** `TestAGC001OwnerInventory`.
- **Key limitation:** this control cannot pass level 1 from a scan. The `baseline` and `standard` profiles accept level 1 for it. The `high-risk` profile does not, so it needs external evidence there.

### AGC-002 Dynamic Risk Tiering

- **Rule ID:** `AGC-002.declared-tier-too-low`.
- **Counts as declared:** `agent.risk_tier` is `low`, `medium`, or `high` and is not lower than the tier the scanner infers from the agent's capabilities.
- **Reported as a failure:** the declared tier is lower than the inferred tier.
- **Static maximum:** 1.
- **Unit test:** `TestAGC002RiskTier`.
- **Key limitation:** the inferred tier is a heuristic based on detected capabilities. The scanner cannot confirm that a reviewer approved the tier.

### AGC-003 Integrated Change Control

- **Rule IDs:** none. This detector reports present or missing only.
- **Counts as implemented:** a CI workflow that runs on push or pull request and has a step that runs tests or this auditor. GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI files are read.
- **Static maximum:** 2.
- **Unit test:** `TestAGC003ChangeControl`.
- **Key limitation:** any test command counts, even one that does not test the agent. The scanner reads the workflow file. It cannot see whether branch protection makes the check required. An Azure Pipelines file is always treated as running on change.

## Domain B: Identity and Access

### AGC-004 Dedicated Non-Human Identity

- **Rule IDs:** `AGC-004.hardcoded-account-credentials`, `AGC-004.host-credential-mount`.
- **Counts as implemented:** OIDC federation in a GitHub workflow (`id-token: write` with a role or identity provider); a managed or workload identity client in code, such as `DefaultAzureCredential` or `assume_role_with_web_identity`; Kubernetes workload identity annotations; a named Kubernetes service account with a projected token.
- **Reported as a failure:** a user name and a password written close together in code; a hardcoded AWS access key ID; a container volume that mounts host credentials such as `~/.aws`, `~/.ssh`, or `docker.sock`.
- **Static maximum:** 2.
- **Unit test:** `TestAGC004Identity`.
- **Key limitation:** one matching identity pattern anywhere in scope counts. The scanner does not check that the agent's own calls use that identity. When the agent has no detected credential use, the status is "Unknown", not "Missing".

### AGC-005 Allowlisted Tool Access

- **Rule IDs:** `AGC-005.unrestricted-dynamic-dispatch`, `AGC-005.unrestricted-exec-tool`.
- **Counts as implemented:** a membership test against a fixed set of tool names with a reject path close after it (`if name not in ALLOWED_TOOLS:` followed by a raise or return); framework tool scoping arguments such as `allowed_tools` or `activeTools`; an MCP server entry with an allowed-tools list.
- **Reported as a failure:** calling a function looked up by name through `globals()`, `locals()`, `getattr`, or `eval`; a shell or code-execution tool with no restriction in its body.
- **Static maximum:** 2.
- **Unit test:** `TestAGC005Allowlist`.
- **Key limitation:** the reject path must appear within six lines of the test. The dynamic dispatch and unrestricted tool checks are mostly Python. For TypeScript and JavaScript only the `Set.has` / `includes` form and `eval` are recognized.

### AGC-006 Short-Lived Scoped Tokens

- **Rule ID:** `AGC-006.long-lived-token`.
- **Counts as implemented:** a function that issues a token (by name, or by calling `jwt.encode` or `jwt.sign`) with a lifetime of one hour or less and an audience or scope in the same function.
- **Reported as a failure:** a token with expiry turned off, or with a lifetime over 24 hours.
- **Static maximum:** 2.
- **Unit test:** `TestAGC006Tokens`.
- **Key limitation:** this detector never reports "Missing". When the code issues no tokens itself, which is the common case, the status is "Unknown" and needs evidence from your identity provider. Lifetimes between one and 24 hours produce no evidence in either direction. Both examples show "Unknown" here.

### AGC-007 User-Enforced Data Layer

- **Rule IDs:** `AGC-007.sql-built-from-arguments`, `AGC-007.identity-supplied-by-model`.
- **Counts as implemented:** a data function that takes a trusted context (a parameter such as `session`, `ctx`, `principal`, or `current_user`) and uses it in a parameterized SQL `WHERE` clause on an identity column, or in a `filter=` or `namespace=` argument.
- **Reported as a failure:** SQL text built from arguments with an f-string, a template string, `+`, `%`, or `.format`; a tool parameter such as `user_id` or `tenant_id` that the model can fill in.
- **Static maximum:** 2.
- **Unit test:** `TestAGC007DataLayer`.
- **Key limitation:** only SQL and filter keywords are recognized. Data access through an ORM or another data layer needs external evidence. The scanner follows calls two steps from the tool. For most TypeScript and JavaScript tools it does not look inside the tool body, so the result is "Unknown".

### AGC-008 Vault-Injected Secrets

- **Rule ID:** `AGC-008.hardcoded-secret`.
- **Counts as implemented:** a secret manager client (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager, Doppler, Infisical); a Kubernetes `secretKeyRef` or secret volume; `${{ secrets.NAME }}` in CI; Compose secrets.
- **Reported as a failure:** a string that matches a known key format (Anthropic, OpenAI, AWS, GitHub, Slack, a private key block); a value assigned to a secret-like name that is long and random enough and is not a placeholder. Source files, YAML, JSON, TOML, and Dockerfile `ENV` and `ARG` lines are checked.
- **Static maximum:** 2.
- **Unit tests:** `TestAGC008Secrets`, `TestSecretFingerprintIsStableAndValueFree`.
- **Key limitation:** "implemented" means a secret store is used somewhere, not that every secret goes through it. A secret passed in a plain environment variable cannot be told apart from an injected one. Files such as `.env` are not opened, so a secret inside one is not reported. The secret value is never printed in any report.

## Domain C: Action Controls

### AGC-009 External Policy Engine

- **Rule ID:** `AGC-009.policy-fail-open`.
- **Counts as implemented:** an import of a policy engine client (OPA, Cedar, Casbin, Oso, Permit); a call to an OPA data endpoint; a call on the tool path to a local policy function that has a deny branch.
- **Reported as a failure:** an error handler after the policy call that neither stops nor denies, so a policy error lets the action through.
- **Static maximum:** 2.
- **Unit test:** `TestAGC009PolicyEngine`.
- **Key limitation:** an import alone counts as implemented. The scanner does not prove that every sensitive call passes the check. "Missing" is reported only for agents with sensitive actions. When the only policy is a sentence in the system prompt, the finding text says so.

### AGC-010 Human Approval Gates

- **Rule ID:** `AGC-010.auto-approve`.
- **Counts as implemented:** a framework approval setting, such as `interrupt_before`, `needs_approval`, `human_input_mode`, or `requireApproval`; an approval function on the path of a sensitive tool that checks who and what is approved and also checks an expiry or a digest.
- **Reported as a failure:** a sensitive tool parameter such as `auto_approve` that defaults to on; an assignment such as `require_approval = False` anywhere in scope.
- **Static maximum:** 2.
- **Unit test:** `TestAGC010ApprovalGate`.
- **Key limitation:** a framework setting counts wherever it appears. The scanner does not check that it guards the sensitive tool in question. It cannot judge who the approver is. This control applies only to agents with sensitive tools.

### AGC-011 Dual Content Guardrails

- **Rule ID:** `AGC-011.untrusted-content-in-system-prompt`.
- **Counts as implemented:** guardrail or structured-output arguments on a model call, such as `input_guardrails`, `output_type`, or `response_format`; schema validation calls such as `model_validate` or `safeParse`; a guardrail library; a local guard function that rejects input and is called.
- **Reported as a failure:** tool results or retrieved documents placed straight into a system prompt.
- **Static maximum:** 2.
- **Unit test:** `TestAGC011Guardrails`.
- **Key limitation:** one check on either side counts. The scanner does not confirm that both input and output are covered, although the control asks for both. A `response_format` alone is enough for "implemented".

### AGC-012 Multi-Level Resource Limits

- **Rule ID:** `AGC-012.unbounded-loop`.
- **Counts as implemented:** a limit argument on a call, such as `max_iterations`, `recursion_limit`, `max_turns`, `maxSteps`, `timeout`, or `max_tokens`; a step, time, or budget check inside the agent loop.
- **Reported as a failure:** an agent loop written as `while True` with no bound.
- **Static maximum:** 2.
- **Unit test:** `TestAGC012Limits`.
- **Key limitation:** this detector is generous. Any one limit counts, including a lone `timeout=` or `max_tokens=`. The control asks for limits on time, cost, and steps together, and the scanner does not check for all three.

### AGC-013 Disposable Sandbox Environments

- **Rule IDs:** `AGC-013.privileged-container`, `AGC-013.root-container-with-exec-tools`.
- **Counts as implemented:** container configuration that is non-root, has a read-only root filesystem, and drops all capabilities or forbids privilege escalation. In practice this needs a Compose file or a Kubernetes manifest, because a Dockerfile alone cannot state a read-only filesystem.
- **Reported as a failure:** `privileged: true`; a mounted `docker.sock`; a container that runs as root while the agent has shell or code-execution tools.
- **Static maximum:** 2.
- **Unit test:** `TestAGC013Sandbox`.
- **Key limitation:** network and mount restrictions are not checked. A sandbox that is defined outside the repository is invisible. The manifest shows intent. It does not show what is deployed.

## Domain D: Trust Boundaries

### AGC-014 Vetted Tool Supply Chain

- **Rule IDs:** `AGC-014.unpinned-dependencies`, `AGC-014.unpinned-image`, `AGC-014.unpinned-mcp-server`, `AGC-014.unpinned-ci-action`.
- **Counts as implemented:** dependencies, base images, MCP servers, and CI actions were checked and no unpinned item was found.
- **Reported as a failure:** a runtime dependency with no exact version and no lockfile; a base image with no tag or the `latest` tag; an MCP server launched from a registry without a version; a third-party CI action that is not pinned to a commit SHA.
- **Static maximum:** 2.
- **Unit test:** `TestAGC014SupplyChain`.
- **Key limitation:** the scan is offline. It does not look up known vulnerabilities, signatures, or provenance. An image with a version tag and no digest still counts as pinned. Development dependencies are ignored.

### AGC-015 Context Memory Integrity

- **Rule ID:** `AGC-015.shared-memory-write`.
- **Counts as implemented:** a memory write function that takes a user, tenant, or session scope and validates the value before it stores it.
- **Reported as a failure:** a memory write with no scope and no validation that stores raw model output.
- **Static maximum:** 2.
- **Unit test:** `TestAGC015Memory`.
- **Key limitation:** functions are found by name (`memory`, `remember`, `recall`, and write verbs). Memory that a framework manages is invisible. A `raise` anywhere in the function is taken as validation. Applies only to agents with a memory capability.

### AGC-016 Authenticated Inter-Agent Messages

- **Rule IDs:** none.
- **Counts as implemented:** signature or mutual TLS verification (`hmac.compare_digest`, `jwt.decode`, `timingSafeEqual`, certificate requirements) in a function or file whose name relates to messages or agents; `securitySchemes` in an agent card.
- **Static maximum:** 2.
- **Unit test:** `TestAGC016InterAgent`.
- **Key limitation:** a name heuristic with no call following. Replay protection and recipient checks are not verified. Applies only to multi-agent systems. Neither example is one, so this detector has unit tests only.

## Domain E: Containment and Recovery

### AGC-017 Instant Agent Kill Switch

- **Rule ID:** `AGC-017.kill-flag-not-external`.
- **Counts as implemented:** a stop check in the agent loop or the tool dispatcher that reads something an operator can change while the agent runs: a file, an environment variable, a shared store, a signal, or a cancellation token.
- **Reported as declared only, with a finding:** a module-level constant such as `KILL_SWITCH = False` and no external check. A constant cannot be changed without a deployment.
- **Static maximum:** 2.
- **Unit test:** `TestAGC017KillSwitch`.
- **Key limitation:** the list of "external sources" is broad and includes generic calls such as `.get(`. When a framework owns the loop, the scanner can only look for a cancellation hook around it. The constant check is written for Python naming.

### AGC-018 Reversible Action Design

- **Rule IDs:** none.
- **Counts as implemented:** idempotency keys; transactions or rollback calls; a function named for compensation, such as `undo`, `revert`, or `compensate`.
- **Static maximum:** 2.
- **Unit test:** `TestAGC018Reversible`.
- **Key limitation:** the match is made across the agent's files and is not tied to the tools that change data. Any `with db:` block counts. The detector runs only for agents with mutating actions.

### AGC-019 Dedicated Incident Runbook

- **Rule IDs:** none.
- **Counts as declared:** a runbook file (for example `docs/runbooks/incident.md`) that covers at least four of these five topics: owner, escalation, containment, revocation, recovery.
- **Static maximum:** 1. A document is a statement.
- **Unit test:** `TestAGC019Runbook`.
- **Key limitation:** a keyword match on a file. The scanner cannot tell whether the plan was practiced, which the control asks for.

## Domain F: Assurance and Visibility

### AGC-020 Mandatory Regression Evals

- **Rule IDs:** none.
- **Counts as implemented:** at least one test file that asserts a denial (for example `assertRaises` or `pytest.raises` together with words such as `denied`, `forbidden`, or `rejected`), and a CI workflow that runs tests.
- **Static maximum:** 2.
- **Unit test:** `TestAGC020RegressionEvals`.
- **Key limitation:** the tests are not run by the scan, and the CI step is not checked to run those files. Level 3 needs an evidence file from a real test run.

### AGC-021 Continuous Red Teaming

- **Rule IDs:** none.
- **Counts as implemented:** a promptfoo configuration with a `redteam` section; a garak or PyRIT configuration; a dependency on garak, PyRIT, Giskard, promptfoo, or DeepTeam; a test named for injection, jailbreak, adversarial input, or poisoning that contains an assertion.
- **Static maximum:** 2.
- **Unit test:** `TestAGC021RedTeam`.
- **Key limitation:** a dependency alone counts. The scenarios are not run, and "regularly", which the control asks for, cannot be seen in a repository.

### AGC-022 Complete Step Tracing

- **Rule IDs:** `AGC-022.raw-sensitive-logging`, `AGC-022.credential-logging`.
- **Counts as implemented:** a tracing library (OpenTelemetry, LangSmith, Langfuse, Phoenix, Logfire, AgentOps, MLflow, and others) with a span or tracer call; a local trace function that writes a record with a run ID and the tool name.
- **Reported as a failure:** a log or print call that writes a credential, or writes prompts and model output without redaction.
- **Static maximum:** 2.
- **Unit test:** `TestAGC022Tracing`.
- **Key limitation:** the span call match includes generic words such as `configure` and `observe`. "Every step" is not checked. One traced path is enough.

### AGC-023 Tamper-Evident Audit Trail

- **Rule IDs:** none.
- **Counts as implemented:** an audit function that hashes each record together with the previous hash and writes it; an audit function that signs records; storage configuration with object lock, immutability, or append-only settings.
- **Static maximum:** 2.
- **Unit test:** `TestAGC023AuditTrail`.
- **Key limitation:** the storage setting is not linked to where the agent writes. The scanner does not check that anyone verifies the chain. Plain logging is reported as "Missing".

### AGC-024 Real-Time Operational Monitoring

- **Rule IDs:** none.
- **Counts as implemented:** alert rules (Prometheus rules, a CloudWatch alarm, a Datadog monitor, or Terraform monitor resources) that mention an agent signal such as tool use, policy denials, tokens, or approvals.
- **Static maximum:** 2.
- **Unit test:** `TestAGC024Monitoring`.
- **Key limitation:** a keyword match inside an alert file. The scanner cannot see whether the alerts fire or reach a person. Monitoring that is defined outside the repository is invisible.

## What this means in practice

- A status of "Implemented" says the scanner saw a recognized pattern. Treat it as a pointer to code that a reviewer should read, not as proof.
- The detectors for AGC-011, AGC-012, AGC-018, AGC-021, and AGC-022 accept a single weak signal. Expect them to be optimistic.
- The detectors for AGC-005, AGC-007, AGC-009, and AGC-010 follow the tool path and are stricter, mainly for Python.
- AGC-001, AGC-002, AGC-006, and AGC-019 need evidence from outside the code to go above what a scan shows.
- If a detector is wrong about your code, use the "False positive or wrong result" issue template. See [troubleshooting.md](troubleshooting.md#a-result-looks-wrong).

Related pages: [control-catalog.md](control-catalog.md) for the control definitions, [evidence.md](evidence.md) for levels 3 and 4, and [known-limitations.md](known-limitations.md) for limits of the tool as a whole.
