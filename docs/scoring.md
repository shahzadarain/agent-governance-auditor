# Scoring and decisions

AgentGov Auditor reports two separate things for every agent:

1. A **decision**: `ALLOW`, `BLOCK`, or `REVIEW_REQUIRED`. The decision comes
   from mandatory controls and critical findings.
2. A **score** from 0 to 100. The score is an illustration of how much of the
   governance model is verified.

The score never changes the decision. A score is not a certification, not a
compliance statement, and not a probability that the agent is safe.

The logic lives in `internal/policy` (status and decision) and
`internal/scoring` (score). It is deterministic: the same input gives the same
output, and the clock is an input.

## Status of a control

Each of the 24 controls gets exactly one status for each agent.

| Status | Maturity | Meaning |
| --- | --- | --- |
| `verified-operational` | 4 | Runtime or independently verified evidence shows the control works in operation. |
| `verified-tested` | 3 | Tests for this exact version passed. |
| `verified-implementation` | 2 | Code, configuration, or reviewed evidence shows the control is implemented. |
| `declared-only` | 1 | Only a declaration exists. |
| `missing` | 0 | A detector looked and found no mechanism. |
| `failed` | 0 | A violation or a failed test was observed. |
| `unknown` | 0 | The control could not be assessed. |
| `error` | 0 | A collector failed. An error never passes. |
| `accepted-risk` | 0 | A recorded exception. It is not a pass. |
| `not-applicable` | none | The control does not apply. It leaves the score. |

`missing`, `failed`, and `unknown` are different facts and stay separate.
Missing evidence is not proof of a weakness, and unknown coverage is not proof
of safety.

### How the status is derived

Only evidence with `validity: valid` counts. The engine applies these rules in
order and stops at the first that matches.

1. Any `signal: error` gives `error`.
2. Any `signal: violation` gives `failed`.
3. An approved exception in `.agentgov.yaml` gives `accepted-risk` or
   `not-applicable`. When both exist for one control, `accepted-risk` wins,
   because it is the less lenient of the two.
4. A capability-mode control with no triggering capability gives
   `not-applicable` with the basis `inferred`.
5. The strongest `signal: present` evidence gives `verified-operational`,
   `verified-tested`, or `verified-implementation`.
6. Only `signal: declared` evidence gives `declared-only`.
7. Only `signal: absent` evidence gives `missing`.
8. Nothing gives `unknown`.

Rules 1 and 2 come first on purpose. An exception or an inferred
not-applicable result cannot hide a recorded violation or a collector error.
In that case the control counts as applicable.

### Limits on credit

- **Static evidence is capped.** Evidence with the source `static` or
  `configuration` never gives more than the `max_static_maturity` of the
  control (2 for most controls, 1 for AGC-001, AGC-002, and AGC-019). The
  strength that the evidence claims for itself does not matter. An evidence
  source that the engine does not recognize is treated the same way.
- **Levels 3 and 4 need independent evidence.** Only the sources `test`,
  `runtime`, `external-attestation`, and `manual-review` can give level 3 or 4.
- **Signed evidence.** When the profile sets `require_signed_evidence`, test
  and runtime evidence gives level 3 or 4 only with `integrity: verified`.
  Unsigned evidence is credited up to level 2, and the status reason says so.
- **A declaration stays a declaration.** Evidence with `signal: declared`
  gives level 1, whatever strength it claims.

### Evidence that is not valid

Evidence that is not valid gives no credit. The evidence stays referenced on
the control, so the reason can be traced. The status reason names the cause:

| Cause | Status reason |
| --- | --- |
| Expired | `Evidence expired on 2026-01-01.` |
| Different commit | `Evidence is bound to a different commit.` |
| Subject files changed | `Evidence is bound to files that changed after it was collected.` |
| Bad signature | `Evidence signature failed verification.` |
| No binding | `Evidence is not bound to a commit or to file content.` |
| Schema failure | `Evidence failed schema validation.` |

The evidence loader sets the validity. The engine adds two checks of its own:
evidence whose `valid_until` is before the scan time counts as expired, and
evidence with `integrity: invalid` counts as a bad signature.

When no evidence exists at all, the reason is: `No detector could assess this
control from source code. Supply test or runtime evidence.`

## The score

```text
score = round(100 * sum(weight_i * maturity_i / 4) / sum(weight_i))
```

The sums run over the applicable controls of one agent.

- A `not-applicable` control is left out of both sums.
- An `accepted-risk` control stays in, at maturity 0.
- `missing`, `failed`, `unknown`, and `error` stay in, at maturity 0.
- Halves round up. The calculation uses integers, so it gives the same result
  on every platform.
- With no applicable control there is no number. The value is `null` and the
  label is `insufficient-evidence`.

Weights come from the control catalog (`default_weight`). A profile can
override single weights. The eight priority controls weigh 5, and the 24
default weights add up to 85.

### Companion measures

| Field | Meaning |
| --- | --- |
| `applicable_controls` | Number of controls in the denominator. |
| `controls_with_evidence`, `coverage_percent` | Applicable controls with at least one valid evidence item, of any signal except `error`. |
| `tested_percent` | Applicable controls at maturity 3 or 4. |
| `operational_percent` | Applicable controls at maturity 4. |
| `findings_by_severity` | Count of findings for each of the five severities. |
| `status_counts` | Count of each of the ten statuses over all 24 controls. |
| `unresolved_mandatory` | Mandatory controls that do not meet the profile. |

### Worked example

The numbers below come from the engine. The test `TestWorkedExample` in
`internal/policy/evaluate_test.go` pins them.

An agent named `support-agent` has two detected capabilities: `tools` and
`data-access`. The profile is `standard`.

Seven capability-mode controls have no triggering capability and are
`not-applicable` by inference: AGC-006, AGC-009, AGC-010, AGC-013, AGC-015,
AGC-016, and AGC-018. Their weights (3 + 5 + 5 + 3 + 3 + 3 + 2 = 24) leave the
denominator. That leaves 17 applicable controls with a total weight of
85 - 24 = 61.

| Control | Evidence | Status | Maturity | Weight | Weight x maturity |
| --- | --- | --- | --- | --- | --- |
| AGC-001 | Declared owner in configuration | `declared-only` | 1 | 5 | 5 |
| AGC-004 | Violation: shared staff account | `failed` | 0 | 5 | 0 |
| AGC-005 | Passing allowlist test | `verified-tested` | 3 | 5 | 15 |
| AGC-007 | Static: user filter found | `verified-implementation` | 2 | 5 | 10 |
| AGC-008 | Static: secret manager, no hardcoded secret | `verified-implementation` | 2 | 4 | 8 |
| AGC-012 | Static: step limit and timeout | `verified-implementation` | 2 | 3 | 6 |
| AGC-020 | Detector found no governance tests | `missing` | 0 | 4 | 0 |
| AGC-022 | Runtime trace evidence | `verified-operational` | 4 | 5 | 20 |
| 9 other applicable controls | None | `unknown` | 0 | 25 | 0 |
| **Total** | | | | **61** | **64** |

```text
score = round(100 * 64 / (4 * 61)) = round(26.23) = 26
```

Result:

- Score: `26/100`.
- Coverage: 8 of 17 applicable controls have valid evidence, 47 percent.
- Tested: 2 of 17 (AGC-005 and AGC-022), 12 percent.
- Operational: 1 of 17 (AGC-022), 6 percent.
- Decision: `BLOCK`, with three reasons in control order:
  - `mandatory-control-failed` on AGC-004;
  - `mandatory-not-applicable-inferred` on AGC-010;
  - `mandatory-control-unknown` on AGC-017.

AGC-001 raises no reason. It is `declared-only` at maturity 1, and the
`standard` profile requires maturity 1 for that control (see the per-control
minimum in `docs/policy-reference.md`). Under `high-risk` the same result
would raise `mandatory-below-min-maturity`.

## Why a high score cannot override a mandatory failure

The decision code never reads the score. It reads the status and maturity of
each mandatory control, and the severity of each finding. The test
`TestHighScoreCannotOverrideMandatoryFailure` proves the property with real
numbers:

- An agent has 23 controls at maturity 4 and one mandatory control, AGC-008,
  `failed` because of a hardcoded secret. The score is `95/100`. The decision
  is `BLOCK` with the reason `mandatory-control-failed`, under all three
  profiles.
- An agent has all 24 controls at maturity 4, so the score is `100/100`. One
  critical finding is open. The decision is `BLOCK` with the reason
  `critical-finding`. This holds when the finding is on a mandatory control
  and when it is on a control that is not mandatory.
- An agent has all 24 controls supported by operational evidence, and one
  collector error on a mandatory control. The decision is `BLOCK` with the
  reason `mandatory-control-error`.

The reverse also holds. An agent with a low score is allowed when every
mandatory control meets the profile and no critical finding is open. The score
shows how much is verified. The decision shows whether the policy is met.

## Decisions

For each agent the engine checks every mandatory control of the effective
profile, in control order, and every finding.

| Reason code | Raised when | Class |
| --- | --- | --- |
| `mandatory-control-failed` | A mandatory control is `failed`. | Block |
| `mandatory-control-error` | A mandatory control is `error`. | Block |
| `mandatory-evidence-invalid` | A mandatory control falls short, and evidence that could have supported it was expired, mismatched, unbound, malformed, or had a bad signature. | Block |
| `critical-finding` | Any finding of critical severity is open, on any control. | Block |
| `mandatory-control-missing` | A mandatory control is `missing`. | Block, or review with a review workflow |
| `mandatory-control-unknown` | A mandatory control is `unknown`, or the catalog does not define it. | Block, or review with a review workflow |
| `mandatory-below-min-maturity` | A mandatory control is below its required maturity: the per-control minimum of the profile when one is set, otherwise the general minimum. | Block, or review with a review workflow |
| `mandatory-accepted-risk` | A mandatory control has an accepted risk. | Review |
| `mandatory-not-applicable-inferred` | A mandatory control is `not-applicable` by inference, with no approved exception. | Review |
| `review-workflow` | The profile enables a review workflow, and at least one shortfall became a review item. | Review |
| `policy-satisfied` | Nothing above applies. | Allow |
| `no-agent-detected` | The scan found no agent. | Review |
| `policy-input-invalid` | The engine was called without a catalog or a profile. | Block |

Outcome for one agent:

- Any block-class reason gives `BLOCK`.
- Otherwise any review-class reason gives `REVIEW_REQUIRED`.
- Otherwise the outcome is `ALLOW`, with the single reason `policy-satisfied`.

A mandatory control with an approved `not_applicable` exception meets the
policy and raises no reason.

With `review_workflow: true` in the profile, the `missing`, `unknown`, and
`below-min-maturity` shortfalls give `REVIEW_REQUIRED` in place of `BLOCK`. The
reasons `failed`, `error`, `evidence-invalid`, and `critical-finding` always
block. `REVIEW_REQUIRED` is never a pass.

Each reason carries the code, the control ID, the agent ID, and a message in
plain language.

## Repository level

- **No agent detected**: the assessments list is empty, the score has no value
  and the label `insufficient-evidence`, and the decision is `REVIEW_REQUIRED`
  with the reason `no-agent-detected`. This is not a pass. Nothing was
  assessed.
- **One or more agents**: the repository score is the score of the
  lowest-scoring agent. A tie goes to the first agent ID in alphabetical
  order. An agent whose score has no value ranks lowest. The repository
  decision is the most restrictive agent decision (`BLOCK`, then
  `REVIEW_REQUIRED`, then `ALLOW`), and its reasons are the reasons of all
  agents in agent-ID order.

At repository level, two fields of the score cover the whole repository
instead of the lowest-scoring agent: `findings_by_severity` counts every
finding, and `unresolved_mandatory` lists the unresolved mandatory controls of
all agents.

Evidence and findings with the agent ID `*` apply to every agent.

## What the score is not

- It is not a certification or an attestation of compliance with any standard.
- It is not a probability of safety or a measure of residual risk.
- It is not comparable between scans made with different policy versions,
  profiles, or weights.
- It does not replace a penetration test, an audit, or a security review.
