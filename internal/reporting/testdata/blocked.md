## AgentGov Auditor report

**Release decision: BLOCK.** Do not release until the listed controls are fixed.

**Assessment maturity: 21/100** (illustrative only). 18 of 22 applicable controls have evidence. Verified by tests: 14%. Verified in operation: 5%.

| Target | Profile | Commit | Policy | Offline |
|---|---|---|---|---|
| vulnerable-agent | high-risk (set in the configuration file) | 4f9c2d7 | builtin/v1 1.0 | yes |

### Agents

- **finance-processing-agent**: langgraph, python, detected (high confidence), 4 tools

### Control summary

| Group | Controls | Meaning |
|---|---:|---|
| Verified | 3 | Test or operational evidence shows the control works. |
| Partial | 7 | The control is implemented or declared but not proven by tests, or a recorded exception covers it. |
| Unknown | 4 | There is not enough evidence to assess the control. |
| Failed | 8 | The control failed, is missing, or could not be checked because of an error. |
| Not applicable | 2 | The control does not apply and is left out of the score. |

### Top findings

| Severity | Control | Finding | Location |
|---|---|---|---|
| Critical | AGC-007 | Invoice lookup does not filter by the current user | src/agent/retrieval.py:42 |
| Critical | AGC-008 | Credential written in source code | src/agent/config.py:9 |
| Critical | AGC-010 | Refunds run without an enforced approval | src/actions.py:86 |
| High | AGC-004 | Agent uses a shared service account | src/agent/config.py:14 |
| High | AGC-009 | No policy check before sensitive tools | No file location |
| Medium | AGC-005 | Shell tool is not in the declared tool list | src/actions.py:131 |
| Medium | AGC-014 | MCP server version is not pinned | mcp.json:7 |
| Low | AGC-023 | Audit records are plain application logs | No file location |

Findings by severity: 3 critical, 2 high, 2 medium, 1 low, 0 info.

### Unresolved mandatory controls

- **AGC-007 User-Enforced Data Layer** (Failed). Next action: Enforce caller-specific authorization in the data service.
- **AGC-008 Vault-Injected Secrets** (Failed). Next action: Remove the value from the code and rotate the credential.
- **AGC-010 Human Approval Gates** (Failed). Next action: Require an external approval bound to the actor, the exact action, and an expiry time.
- **AGC-001 Owner and Inventory** (Declared only). Next action: Attach a signed owner attestation or a registry record as evidence.
- **AGC-004 Dedicated Non-Human Identity** (Failed). Next action: Create a dedicated workload identity for the agent.
- **AGC-009 External Policy Engine** (Missing). Next action: Route sensitive tool calls through a policy enforcement point.
- **AGC-020 Mandatory Regression Evals** (Assessment error). Next action: Fix the test report and scan again.
- **AGC-013 Disposable Sandbox Environments** (Accepted risk). Next action: Have a reviewer confirm that the exception is still acceptable.

<details>
<summary>All 24 control results</summary>

| Control | Title | Domain | Status | Maturity | Mandatory |
|---|---|---|---|---:|---|
| AGC-001 | Owner and Inventory | A: Accountability | Declared only | 1/4 | yes |
| AGC-002 | Dynamic Risk Tiering | A: Accountability | Implemented (not yet tested) | 2/4 | no |
| AGC-003 | Integrated Change Control | A: Accountability | Unknown (needs evidence) | 0/4 | no |
| AGC-004 | Dedicated Non-Human Identity | B: Identity and Access | Failed | 0/4 | yes |
| AGC-005 | Allowlisted Tool Access | B: Identity and Access | Verified by tests | 3/4 | yes |
| AGC-006 | Short-Lived Scoped Tokens | B: Identity and Access | Unknown (needs evidence) | 0/4 | no |
| AGC-007 | User-Enforced Data Layer | B: Identity and Access | Failed | 0/4 | yes |
| AGC-008 | Vault-Injected Secrets | B: Identity and Access | Failed | 0/4 | yes |
| AGC-009 | External Policy Engine | C: Action Controls | Missing | 0/4 | yes |
| AGC-010 | Human Approval Gates | C: Action Controls | Failed | 0/4 | yes |
| AGC-011 | Dual Content Guardrails | C: Action Controls | Implemented (not yet tested) | 2/4 | no |
| AGC-012 | Multi-Level Resource Limits | C: Action Controls | Verified in operation | 4/4 | yes |
| AGC-013 | Disposable Sandbox Environments | C: Action Controls | Accepted risk | 0/4 | yes |
| AGC-014 | Vetted Tool Supply Chain | D: Trust Boundaries | Missing | 0/4 | no |
| AGC-015 | Context Memory Integrity | D: Trust Boundaries | Not applicable | - | no |
| AGC-016 | Authenticated Inter-Agent Messages | D: Trust Boundaries | Not applicable | - | no |
| AGC-017 | Instant Agent Kill Switch | E: Containment and Recovery | Implemented (not yet tested) | 2/4 | yes |
| AGC-018 | Reversible Action Design | E: Containment and Recovery | Declared only | 1/4 | no |
| AGC-019 | Dedicated Incident Runbook | E: Containment and Recovery | Declared only | 1/4 | no |
| AGC-020 | Mandatory Regression Evals | F: Assurance and Visibility | Assessment error | 0/4 | yes |
| AGC-021 | Continuous Red Teaming | F: Assurance and Visibility | Unknown (needs evidence) | 0/4 | no |
| AGC-022 | Complete Step Tracing | F: Assurance and Visibility | Verified by tests | 3/4 | yes |
| AGC-023 | Tamper-Evident Audit Trail | F: Assurance and Visibility | Missing | 0/4 | no |
| AGC-024 | Real-Time Operational Monitoring | F: Assurance and Visibility | Unknown (needs evidence) | 0/4 | no |

</details>

2 scan warnings. See the full report for details.

---

Generated by AgentGov Auditor 0.1.0. This is an evidence-based assessment, not a certification.
