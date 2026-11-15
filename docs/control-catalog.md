# Control catalog

AgentGov Auditor assesses 24 controls in six domains. The controls are this
project's own governance model. They are not an official standard, and a scan
result is not a certification.

The catalog is versioned policy data. Pack `builtin/v1`, version `1.0`. The
source files are `policies/controls/v1/AGC-001.yaml` to `AGC-024.yaml`, one
file per control, embedded in the binary. Each file is checked against
`policies/schema/control.schema.json` and against semantic rules every time the
catalog loads. A broken catalog stops the scan. It never produces a partial
assessment.

The tables below were generated from the loaded catalog.

## How to read the tables

- **In plain language**: one sentence that explains the control without
  security terms. Every report shows it.
- **Applies**: `Always` means the control applies to every agent. Otherwise the
  control applies when the scan detects one of the listed capabilities, or
  when `.agentgov.yaml` declares it. When no listed capability is found, the
  status is `not-applicable` with the basis `inferred`. That is an inference,
  not an approval.
- **Max static maturity**: the highest verification level that source code and
  configuration alone can support. A value of 2 means a static scan can show
  that the control is implemented. A value of 1 means a static scan can only
  see a declaration, so a reviewer, an attestation, a test, or runtime
  evidence is needed for more. No static evidence ever supports level 3 or 4.
- **Default weight**: the weight of the control in the illustrative score. The
  eight priority controls weigh 5. The weights of all 24 controls add up to
  85. A profile can override a weight. Weights never affect the
  decision.

## The 24 controls

### Domain A: Accountability

| ID | Title | In plain language | Applies | Max static maturity | Default weight |
| --- | --- | --- | --- | --- | --- |
| AGC-001 | Owner and Inventory | A named person or team must be responsible for the agent, and the agent must be listed with what it does and what it can use. | Always | 1 | 5 |
| AGC-002 | Dynamic Risk Tiering | The agent must have a risk level that matches what it can really do, and someone must explain and approve that level. | Always | 1 | 2 |
| AGC-003 | Integrated Change Control | When the agent's model, tools, or permissions change, the change must be reviewed and checked again before release. | Always | 2 | 3 |

### Domain B: Identity and Access

| ID | Title | In plain language | Applies | Max static maturity | Default weight |
| --- | --- | --- | --- | --- | --- |
| AGC-004 | Dedicated Non-Human Identity | The agent must use its own account, not a staff member's login or a shared password. | Always | 2 | 5 |
| AGC-005 | Allowlisted Tool Access | The agent may use only the tools on an approved list, and everything else must be refused. | When the agent has: tools | 2 | 5 |
| AGC-006 | Short-Lived Scoped Tokens | The agent's access keys must expire quickly and must open only what the agent needs. | When the agent has: credentials | 2 | 3 |
| AGC-007 | User-Enforced Data Layer | The agent must only fetch data that the person it is working for is allowed to see. | When the agent has: data-access | 2 | 5 |
| AGC-008 | Vault-Injected Secrets | Passwords and keys must never be written in the code, and a secure store must supply them when the agent runs. | Always | 2 | 4 |

### Domain C: Action Controls

| ID | Title | In plain language | Applies | Max static maturity | Default weight |
| --- | --- | --- | --- | --- | --- |
| AGC-009 | External Policy Engine | Fixed rules outside the AI model must decide whether a risky action is allowed, and the answer must be no when the rules cannot be checked. | When the agent has: sensitive-actions, mutating-actions, shell-exec, code-exec | 2 | 5 |
| AGC-010 | Human Approval Gates | A person must approve risky actions before the agent carries them out. | When the agent has: sensitive-actions | 2 | 5 |
| AGC-011 | Dual Content Guardrails | What goes into the agent and what comes out must both be checked, so hidden instructions and sensitive data do not slip through. | Always | 2 | 3 |
| AGC-012 | Multi-Level Resource Limits | The agent must have firm limits on how long it runs, how much it spends, and how many actions it takes. | Always | 2 | 3 |
| AGC-013 | Disposable Sandbox Environments | Anything the agent runs must happen in a locked-down, throwaway workspace that cannot harm real systems. | When the agent has: shell-exec, code-exec, container | 2 | 3 |

### Domain D: Trust Boundaries

| ID | Title | In plain language | Applies | Max static maturity | Default weight |
| --- | --- | --- | --- | --- | --- |
| AGC-014 | Vetted Tool Supply Chain | The outside tools and software the agent relies on must come from known sources and be fixed to checked versions. | Always | 2 | 3 |
| AGC-015 | Context Memory Integrity | What the agent remembers must be checked before it is saved, kept separate for each user, and protected from tampering. | When the agent has: memory | 2 | 3 |
| AGC-016 | Authenticated Inter-Agent Messages | When agents talk to each other, each one must prove who it is, and messages must be protected from forgery. | When the agent has: multi-agent | 2 | 3 |

### Domain E: Containment and Recovery

| ID | Title | In plain language | Applies | Max static maturity | Default weight |
| --- | --- | --- | --- | --- | --- |
| AGC-017 | Instant Agent Kill Switch | Someone must be able to stop the agent immediately, and the stop must actually end its actions. | Always | 2 | 5 |
| AGC-018 | Reversible Action Design | When the agent changes something, there must be a way to undo it, or a clear approval for anything that cannot be undone. | When the agent has: mutating-actions, sensitive-actions | 2 | 2 |
| AGC-019 | Dedicated Incident Runbook | There must be a written and practiced plan for what to do when the agent goes wrong. | Always | 1 | 2 |

### Domain F: Assurance and Visibility

| ID | Title | In plain language | Applies | Max static maturity | Default weight |
| --- | --- | --- | --- | --- | --- |
| AGC-020 | Mandatory Regression Evals | The agent must pass a fixed set of tests, covering what it should and should not do, before every release. | Always | 2 | 4 |
| AGC-021 | Continuous Red Teaming | People or tools must regularly try to trick or break the agent, in a safe test setting, to find weaknesses first. | Always | 2 | 2 |
| AGC-022 | Complete Step Tracing | Every step the agent takes must be recorded so people can later see exactly what it did and why. | Always | 2 | 5 |
| AGC-023 | Tamper-Evident Audit Trail | The record of what the agent did must be protected so that nobody can secretly change or delete it. | Always | 2 | 3 |
| AGC-024 | Real-Time Operational Monitoring | The agent must be watched while it runs, and unusual behavior must raise an alert that reaches a person. | Always | 2 | 2 |

## What each control file holds

| Field | Purpose |
| --- | --- |
| `id`, `title`, `domain` | Identity of the control. |
| `intent` | Why the control exists. |
| `plain_language` | The one-sentence explanation for readers with no security training. |
| `applicability` | `always`, or `capability` with the triggering capabilities and a rationale. |
| `evidence_types` | The evidence sources that can support the control. |
| `detectors` | The rule-ID prefix of the detectors for the control, for example `AGC-010.*`. |
| `dynamic_tests` | The synthetic test scenarios that would prove the control. |
| `verification_rules` | What implementation, tested, and operational mean for this control, and `max_static_maturity`. |
| `remediation` | Three to five ordered steps. |
| `severity`, `default_weight` | Default severity and score weight. |
| `standards_mappings` | Verified references to published standards. May be empty. |
| `limitations` | What the scan cannot establish for this control. |
| `examples` | One positive and one negative evidence example. |

## Standards mappings

Mappings are references that help a reader find related published material.
They are not a certification, an endorsement, or a claim of conformance. This
project is not affiliated with or approved by OWASP or NIST. The catalog
stores the standard name, the version, the requirement identifier, the source
URL, and a rationale written in this project's own words. It does not copy
text from any standard.

### What was verified, when, and where

Verification date: 2026-11-15.

**OWASP Top 10 for Agentic Applications for 2026**

- Document page: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>.
  Fetched on the verification date. The page confirms the document title and
  the publication date of 9 December 2025. The page does not state a separate
  version number, so the catalog records the version as `2026`, the edition
  named in the title. The page does not list the ten identifiers.
- Identifiers: verified on the OWASP GenAI Security Project announcement page,
  <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>,
  fetched on the verification date. It lists all ten identifiers: ASI01 Agent
  Goal Hijack, ASI02 Tool Misuse, ASI03 Identity and Privilege Abuse, ASI04
  Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06
  Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication,
  ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue
  Agents.
- Limits of this verification: the identifiers and titles were confirmed. The
  full text of each entry in the downloadable document was not read. A search
  result on the same date showed the title of ASI02 with the longer wording
  "Tool Misuse and Exploitation". The catalog stores identifiers, not titles,
  so this difference does not affect the data. Each rationale relates a
  control to the subject named by the entry title. ASI09 is verified but not
  used by any control.

**NIST AI Risk Management Framework 1.0**

- <https://www.nist.gov/itl/ai-risk-management-framework>, fetched on the
  verification date. It confirms the framework name, version 1.0, and the
  release date of 26 January 2023. It notes that a revision is in progress.
- <https://airc.nist.gov/airmf-resources/airmf/5-sec-core/>, fetched on the
  verification date. It confirms the four core functions: GOVERN, MAP,
  MEASURE, and MANAGE. The catalog maps to functions only. It does not use
  category or subcategory identifiers, because those were not verified.

**Not verified, and therefore not used**

OWASP AISVS requirement identifiers, the OWASP Agent Control Standard, and
MITRE ATLAS technique identifiers were not verified on the verification date.
The catalog contains no mapping to them.

### Mappings in the catalog

Three controls have no mapping, because no verified entry relates to them
closely enough: AGC-003, AGC-022, and AGC-023. An empty list is the correct
value when nothing was verified.

| Control | Standard | Version | Requirement | Why the control relates to it |
| --- | --- | --- | --- | --- |
| AGC-001 | NIST AI Risk Management Framework | 1.0 | GOVERN | A named owner and an inventory entry are basic accountability structures for an AI system. |
| AGC-002 | NIST AI Risk Management Framework | 1.0 | MAP | Assigning a risk tier from capabilities and impact is a way to establish context and identify risks for the system. |
| AGC-003 | None verified | | | |
| AGC-004 | OWASP Top 10 for Agentic Applications | 2026 | ASI03 | A dedicated identity for each agent limits the damage when an identity or its privileges are abused. |
| AGC-005 | OWASP Top 10 for Agentic Applications | 2026 | ASI02 | A deny-by-default tool allowlist reduces the set of tools an agent can be led to misuse. |
| AGC-006 | OWASP Top 10 for Agentic Applications | 2026 | ASI03 | Short lifetimes and narrow scopes reduce what a stolen or misused agent credential can do. |
| AGC-007 | OWASP Top 10 for Agentic Applications | 2026 | ASI03 | Applying the end user's permissions at the data layer stops an agent's broad access from being used to reach another user's data. |
| AGC-008 | OWASP Top 10 for Agentic Applications | 2026 | ASI03 | Keeping credentials out of source code removes an easy route to taking over the agent's identity and privileges. |
| AGC-009 | OWASP Top 10 for Agentic Applications | 2026 | ASI02 | A deterministic policy check in front of sensitive tools limits how far a misled agent can misuse them. |
| AGC-010 | OWASP Top 10 for Agentic Applications | 2026 | ASI02 | A human decision in front of sensitive tools stops a misled agent from completing a harmful tool action on its own. |
| AGC-011 | OWASP Top 10 for Agentic Applications | 2026 | ASI01 | Checks on untrusted input and on output make it harder for injected content to redirect the agent's goal. |
| AGC-012 | OWASP Top 10 for Agentic Applications | 2026 | ASI08 | Hard limits on steps, cost, and requests keep one fault from spreading into repeated or widening failures. |
| AGC-013 | OWASP Top 10 for Agentic Applications | 2026 | ASI05 | An isolated, disposable execution environment contains the effect of code that the agent should not have run. |
| AGC-014 | OWASP Top 10 for Agentic Applications | 2026 | ASI04 | Pinning and verifying tools, MCP servers, and dependencies addresses weaknesses in the agent's supply chain. |
| AGC-015 | OWASP Top 10 for Agentic Applications | 2026 | ASI06 | Validation, isolation, and provenance for stored memory address the poisoning of an agent's memory and context. |
| AGC-016 | OWASP Top 10 for Agentic Applications | 2026 | ASI07 | Authenticated, integrity-protected messages address insecure communication between agents. |
| AGC-017 | OWASP Top 10 for Agentic Applications | 2026 | ASI10 | A reliable stop mechanism is the last line of containment for an agent that acts outside its intended behavior. |
| AGC-018 | OWASP Top 10 for Agentic Applications | 2026 | ASI08 | Actions that can be rolled back or compensated limit how far the effects of one faulty action spread. |
| AGC-019 | NIST AI Risk Management Framework | 1.0 | MANAGE | A practiced incident procedure is a planned response to risks that have been identified for the system. |
| AGC-020 | NIST AI Risk Management Framework | 1.0 | MEASURE | Repeatable tests that run on each change are a method to analyze and track the system's risks over time. |
| AGC-021 | NIST AI Risk Management Framework | 1.0 | MEASURE | Recurring adversarial tests are a method to assess how the system behaves under hostile conditions. |
| AGC-022 | None verified | | | |
| AGC-023 | None verified | | | |
| AGC-024 | NIST AI Risk Management Framework | 1.0 | MANAGE | Live monitoring with alerts is part of the ongoing monitoring of and response to identified risks. |

A test in `internal/controls` fails when a control file uses a standard,
version, URL, or identifier that is not in the verified list above. To add a
mapping, verify it against the published source first, record it in this
section, and then extend that test.

## Limitations of the catalog

- The 24 controls reflect one project's view of agent governance. They do not
  cover every risk, and they are not a substitute for an audit, a penetration
  test, or legal advice.
- Each control lists its own limitations. Reports show them next to the
  result.
- Detectors exist only for patterns that can be tested. A control with no
  matching detector result is reported as `unknown`, never as passing.
