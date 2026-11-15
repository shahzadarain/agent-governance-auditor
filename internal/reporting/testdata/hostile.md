## AgentGov Auditor report

**Release decision: BLOCK.** Do not release until the listed controls are fixed.

**Assessment maturity: 21/100** (illustrative only). 18 of 22 applicable controls have evidence. Verified by tests: 14%. Verified in operation: 5%.

| Target | Profile | Commit | Policy | Offline |
|---|---|---|---|---|
| repo&lt;script&gt;alert\(1\)&lt;/script&gt;red | high-risk" onmouseover="alert\(1\) (set in the configuration file) | 4f9c2d7 | builtin/v1 1.0 | yes |

### Agents

- **&lt;script&gt;alert\(1\)&lt;/script&gt;" onmouseover="alert\(1\)red**: langgraphcell \| injected \| cells, python, detected (high confidence), 4 tools

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
| Critical | AGC-007 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | src/evil&lt;script&gt;alert\(1\)&lt;/script&gt; \]\(javascript:alert\(1\)\)\|.py:42 |
| Critical | AGC-008 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | src/evil&lt;script&gt;alert\(1\)&lt;/script&gt; \]\(javascript:alert\(1\)\)\|.py:9 |
| Critical | AGC-010 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | src/evil&lt;script&gt;alert\(1\)&lt;/script&gt; \]\(javascript:alert\(1\)\)\|.py:86 |
| High | AGC-004 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | src/evil&lt;script&gt;alert\(1\)&lt;/script&gt; \]\(javascript:alert\(1\)\)\|.py:14 |
| High | AGC-009 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | No file location |
| Medium | AGC-005 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | src/evil&lt;script&gt;alert\(1\)&lt;/script&gt; \]\(javascript:alert\(1\)\)\|.py:131 |
| Medium | AGC-014 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | src/evil&lt;script&gt;alert\(1\)&lt;/script&gt; \]\(javascript:alert\(1\)\)\|.py:7 |
| Low | AGC-023 | &lt;script&gt;alert\(1\)&lt;/script&gt; cell \| injected \| cells \]\(javascript:alert\(1\)\) &lt;\!-- hidden \`\`\` \# Injected heading \`\`\` " onmouseover="alert\(1\) | No file location |

Findings by severity: 3 critical, 2 high, 2 medium, 1 low, 0 info.

### Unresolved mandatory controls

- **AGC-007 User-Enforced Data Layer &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Failed). Next action: " onmouseover="alert\(1\)&lt;script&gt;alert\(1\)&lt;/script&gt;
- **AGC-008 Vault-Injected Secrets &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Failed). Next action: " onmouseover="alert\(1\)&lt;script&gt;alert\(1\)&lt;/script&gt;
- **AGC-010 Human Approval Gates &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Failed). Next action: " onmouseover="alert\(1\)&lt;script&gt;alert\(1\)&lt;/script&gt;
- **AGC-001 Owner and Inventory &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Declared only). Next action: \`\`\` \# Injected heading \`\`\` &lt;script&gt;alert\(1\)&lt;/script&gt;
- **AGC-004 Dedicated Non-Human Identity &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Failed). Next action: " onmouseover="alert\(1\)&lt;script&gt;alert\(1\)&lt;/script&gt;
- **AGC-009 External Policy Engine &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Missing). Next action: " onmouseover="alert\(1\)&lt;script&gt;alert\(1\)&lt;/script&gt;
- **AGC-020 Mandatory Regression Evals &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Assessment error). Next action: \`\`\` \# Injected heading \`\`\` &lt;script&gt;alert\(1\)&lt;/script&gt;
- **AGC-013 Disposable Sandbox Environments &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells** (Accepted risk). Next action: \`\`\` \# Injected heading \`\`\` &lt;script&gt;alert\(1\)&lt;/script&gt;

<details>
<summary>All 24 control results</summary>

| Control | Title | Domain | Status | Maturity | Mandatory |
|---|---|---|---|---:|---|
| AGC-001 | Owner and Inventory &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | A: Accountability | Declared only | 1/4 | yes |
| AGC-002 | Dynamic Risk Tiering &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | A: Accountability | Implemented (not yet tested) | 2/4 | no |
| AGC-003 | Integrated Change Control &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | A: Accountability | Unknown (needs evidence) | 0/4 | no |
| AGC-004 | Dedicated Non-Human Identity &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | B: Identity and Access | Failed | 0/4 | yes |
| AGC-005 | Allowlisted Tool Access &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | B: Identity and Access | Verified by tests | 3/4 | yes |
| AGC-006 | Short-Lived Scoped Tokens &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | B: Identity and Access | Unknown (needs evidence) | 0/4 | no |
| AGC-007 | User-Enforced Data Layer &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | B: Identity and Access | Failed | 0/4 | yes |
| AGC-008 | Vault-Injected Secrets &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | B: Identity and Access | Failed | 0/4 | yes |
| AGC-009 | External Policy Engine &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | C: Action Controls | Missing | 0/4 | yes |
| AGC-010 | Human Approval Gates &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | C: Action Controls | Failed | 0/4 | yes |
| AGC-011 | Dual Content Guardrails &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | C: Action Controls | Implemented (not yet tested) | 2/4 | no |
| AGC-012 | Multi-Level Resource Limits &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | C: Action Controls | Verified in operation | 4/4 | yes |
| AGC-013 | Disposable Sandbox Environments &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | C: Action Controls | Accepted risk | 0/4 | yes |
| AGC-014 | Vetted Tool Supply Chain &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | D: Trust Boundaries | Missing | 0/4 | no |
| AGC-015 | Context Memory Integrity &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | D: Trust Boundaries | Not applicable | - | no |
| AGC-016 | Authenticated Inter-Agent Messages &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | D: Trust Boundaries | Not applicable | - | no |
| AGC-017 | Instant Agent Kill Switch &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | E: Containment and Recovery | Implemented (not yet tested) | 2/4 | yes |
| AGC-018 | Reversible Action Design &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | E: Containment and Recovery | Declared only | 1/4 | no |
| AGC-019 | Dedicated Incident Runbook &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | E: Containment and Recovery | Declared only | 1/4 | no |
| AGC-020 | Mandatory Regression Evals &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | F: Assurance and Visibility | Assessment error | 0/4 | yes |
| AGC-021 | Continuous Red Teaming &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | F: Assurance and Visibility | Unknown (needs evidence) | 0/4 | no |
| AGC-022 | Complete Step Tracing &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | F: Assurance and Visibility | Verified by tests | 3/4 | yes |
| AGC-023 | Tamper-Evident Audit Trail &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | F: Assurance and Visibility | Missing | 0/4 | no |
| AGC-024 | Real-Time Operational Monitoring &lt;script&gt;alert\(1\)&lt;/script&gt;cell \| injected \| cells | F: Assurance and Visibility | Unknown (needs evidence) | 0/4 | no |

</details>

4 scan warnings. See the full report for details.

---

Generated by AgentGov Auditor 0.1.0&lt;script&gt;alert\(1\)&lt;/script&gt;. This is an evidence-based assessment, not a certification.
