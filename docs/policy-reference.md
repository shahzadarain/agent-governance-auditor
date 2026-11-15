# Policy reference

This page describes the configuration file, the risk profiles, the
organization baseline, exceptions, and the reason codes of a decision. For the
score and the status rules, see `docs/scoring.md`. For the controls, see
`docs/control-catalog.md`.

## Principles

- A configuration file is optional. A scan works with no configuration.
- The configuration is a declaration by the repository author. It is never
  evidence that a control is implemented.
- The configuration can add mandatory controls and raise the minimum
  maturity. It cannot remove a mandatory control or lower the minimum.
- An organization baseline, kept outside the repository, can only tighten the
  result as well, and nothing in the repository can weaken it.
- The profiles are project defaults. They are not an external standard.

## The configuration file

The scanner looks for `.agentgov.yaml`, then `.agentgov.yml`, directly in the
scanned root. It does not search parent directories or subdirectories. A
different file can be given explicitly. `.agentgov.example.yaml` in the
repository root is a complete, commented example.

Loading is strict:

- The file must be a regular file. A symbolic link or a directory is rejected.
- The file must be 256 KiB (262144 bytes) or smaller.
- The file must hold exactly one YAML document, and the document must be a
  mapping. Duplicate keys are rejected.
- An unknown field is a problem, because a misspelled key would otherwise be
  ignored without notice.
- The content is checked against the JSON Schema
  `policies/schema/agentgov-config.schema.json` (draft 2020-12) and against a
  few rules a schema cannot express.

Each diagnostic starts with the path of the field, for example:

```text
policy.mandatory_controls[1]: must be a control ID from AGC-001 to AGC-024
verification.evidence_paths[0]: must be a repository-relative path with forward slashes, with no leading "/", no drive letter, and no ".." segment
agent.ownr: unknown field; check the spelling against docs/policy-reference.md
```

An invalid file is an error. The scanner does not continue with a partly
understood configuration.

### Fields

`schema_version` is required. Every other field is optional.

| Field | Type | Values and rules |
| --- | --- | --- |
| `schema_version` | string | Required. Must be the string `"1"`, in quotes. |
| `agent.id` | string | Letters, digits, `.`, `_`, `-`. Starts with a letter or digit. Up to 128 characters. |
| `agent.root` | path | Repository-relative directory. Default `.`. |
| `agent.owner` | string | The accountable person or team. |
| `agent.description`, `agent.purpose` | string | What the agent does and why. |
| `agent.risk_tier` | enum | `low`, `medium`, `high`. |
| `agent.risk_rationale` | string | Why the tier is right. |
| `agent.data_classification` | enum | `public`, `internal`, `confidential`, `restricted`. |
| `agent.registry_ref` | string | Reference to the organization's agent inventory. |
| `agent.last_reviewed` | date | `YYYY-MM-DD`. |
| `agent.reviewer` | string | Who reviewed the entry. |
| `agents` | list | For monorepos. Each entry has the `agent` fields, and `id` and `root` are required. IDs must be unique. |
| `capabilities.declared_tools` | list of strings | Tools the agent may call. A non-empty list makes tool controls applicable. |
| `capabilities.sensitive_actions` | list of strings | Actions that move money, delete, send, or change records. A non-empty list makes the sensitive-action controls applicable. |
| `capabilities.external_connectivity` | boolean | Whether the agent reaches outside systems. |
| `verification.profile` | enum | `baseline`, `standard`, `high-risk`. |
| `verification.tests_path` | path | Directory of governance tests. |
| `verification.evidence_paths` | list of paths | Directories of evidence JSON files. Up to 32. |
| `verification.offline` | boolean | Whether the scan may use the network. |
| `policy.pack` | enum | `builtin/v1`. |
| `policy.mandatory_controls` | list of control IDs | Added to the mandatory controls of the profile. |
| `policy.min_maturity` | integer | 0 to 4. A value below the profile minimum has no effect. |
| `policy.not_applicable` | list of exceptions | See Exceptions. |
| `policy.accepted_risks` | list of exceptions | See Exceptions. |
| `report.redact_sensitive_data` | boolean | Redaction in reports. |
| `report.formats` | list of enums | `terminal`, `json`, `markdown`, `html`, `sarif`. |
| `scan.include`, `scan.exclude` | list of paths | Repository-relative glob patterns. Up to 256 each. |
| `scan.max_file_size` | integer | Largest file the scanner reads, in bytes. 1 to 104857600. |

A **path** is repository-relative and uses forward slashes. It must not start
with `/`, must not contain a backslash or a drive letter, and must not contain
a `..` segment. A **control ID** runs from `AGC-001` to `AGC-024`. A **date**
has the form `YYYY-MM-DD` and must be a real calendar date. Dates may be
written with or without quotes.

### Version and migration policy

- `schema_version` names the format of the configuration file. This release
  supports version `"1"` only.
- Within version 1, changes are additive: new optional fields and new enum
  values. A file that is valid today stays valid in later releases that
  support version 1.
- A change that removes a field, renames a field, or changes the meaning of a
  field needs a new schema version.
- A file with an unsupported version is rejected with a diagnostic that names
  the supported version. The scanner never guesses how to read a newer or an
  older format.
- When a version 2 arrives, the release that introduces it will read both
  versions for at least one minor release cycle, will describe each change in
  the release notes, and will state how to convert a version 1 file. Version 1
  support will be removed only in a later release, after a deprecation
  notice.
- The configuration schema version is separate from the policy pack version
  (`builtin/v1`, version `1.0`) and from the scan result schema version.

## Profiles

A profile says which controls are mandatory and how mature they must be. The
three built-in profiles are project defaults. Copy and edit one to make an
organization baseline.

| Profile | For | Mandatory controls | Min maturity | Per-control minimum | Signed evidence | Review workflow |
| --- | --- | --- | --- | --- | --- | --- |
| `baseline` | A lower-risk internal agent | AGC-001, 005, 008, 022 | 2 | AGC-001: 1 | No | No |
| `standard` | An externally available agent, or sensitive data | AGC-001, 004, 005, 007, 008, 010, 012, 017, 022 | 2 | AGC-001: 1 | No | No |
| `high-risk` | Money, privileged access, safety, or confidential data | AGC-001, 004, 005, 007, 008, 009, 010, 012, 017, 020, 022, 023 | 3 | None | Yes | No |

Profile fields (`policies/schema/profile.schema.json`):

| Field | Meaning |
| --- | --- |
| `name`, `version`, `description` | Identity of the profile. |
| `mandatory_controls` | Controls that decide the outcome. |
| `min_maturity` | Required maturity for every mandatory control, 0 to 4. |
| `control_min_maturity` | Optional map from control ID to a required maturity, 0 to 4. It replaces `min_maturity` for that control and may be lower or higher. |
| `require_signed_evidence` | When true, levels 3 and 4 need evidence with `integrity: verified`. |
| `review_workflow` | When true, the `missing`, `unknown`, and below-minimum shortfalls give `REVIEW_REQUIRED` in place of `BLOCK`. Failures, errors, invalid evidence, and critical findings still block. |
| `weights` | Optional overrides of control weights. They change the score only. |

Note on AGC-001 (Owner and Inventory): a static scan can only see a
declaration for this control, so it can support maturity 1 at most. The
`baseline` and `standard` profiles accept that and set
`control_min_maturity: {AGC-001: 1}`. A schema-valid owner declaration in
`.agentgov.yaml` meets the control under these two profiles. With no
declaration at all the control is `unknown` and still blocks. The `high-risk`
profile sets no override, so AGC-001 must reach maturity 3 there, which needs
reviewed or attested evidence with a verified signature.

The required maturity of a mandatory control is the per-control value when
one is set, otherwise `min_maturity`. Reports show the effective value in the
`min_maturity` field of each control result.

### How the profile is chosen

`policy.SelectProfileName` applies this order and reports the source:

1. The command-line flag. Source `flag`.
2. `verification.profile` in the configuration. Source `config`.
3. The highest risk tier among the detected agents: `high` gives `high-risk`,
   `medium` gives `standard`, `low` gives `baseline`. Source `inferred`. A
   declared tier that is higher than the inferred tier raises the choice
   (source `config`). A declared tier that is lower never lowers it.
4. `baseline`. Source `default`.

The configuration can name a profile that is weaker than the inferred tier
suggests. `policy.ProfileRank` orders the built-in profiles (baseline 1,
standard 2, high-risk 3), so a caller can warn about that. To prevent it in
protected pipelines, use an organization baseline.

### The effective profile

`policy.Effective(base, config, baseline)` builds the profile that the scan
enforces. Each source can only tighten.

| Setting | Rule |
| --- | --- |
| Mandatory controls | The union of the profile, the configuration, and the baseline. Nothing is removed. |
| Minimum maturity | The highest of the three values. |
| Per-control minimum | A control with an explicit per-control value in the base profile keeps that value when the configuration or the baseline raise only the general `min_maturity`. It is raised only when a baseline names it in `control_min_maturity` with a higher value. A baseline entry lower than the current requirement is ignored. A control with no per-control value follows the general minimum. No control ends below the requirement of the base profile. |
| Signed evidence | Required when the profile or the baseline requires it. |
| Review workflow | On only when the profile enables it and the baseline, when present, enables it too. |
| Weights | The profile weights, with baseline weights taking precedence. |

Attempts to weaken are ignored without error: `min_maturity: 0`, an empty
`mandatory_controls` list, a list that names fewer controls, and a baseline
`control_min_maturity` entry below the current requirement all leave the
profile as it is. The configuration file has no per-control minimum field.

Example: under `standard`, AGC-001 requires maturity 1. A configuration or a
baseline with `min_maturity: 3` raises every other mandatory control to 3.
AGC-001 stays at 1, because a static scan cannot give it more and the base
profile states that exception explicitly. A baseline that lists
`control_min_maturity: {AGC-001: 3}` raises AGC-001 to 3. Under `high-risk`
there is no such exception, so AGC-001 follows the general minimum.

The version of the effective profile records what was merged. It gains the
suffix `+config` when the configuration tightened the profile, and
`+baseline.<name>.<version>` when a baseline was applied. Scans with different
effective versions are not directly comparable.

## Organization baseline (baseline lock)

A baseline is a profile YAML file that the organization keeps outside the
scanned repository, for example in a protected CI location.
`policy.LoadBaseline(path)` reads it, checks it against the profile schema,
and limits its size to 256 KiB. The caller is responsible for taking the path
from a trusted place, such as a protected CI variable, and not from the
repository under scan.

The baseline is merged after the configuration, with the same tighten-only
rules, so it wins on strictness. A pull request that edits `.agentgov.yaml`
cannot remove a control the baseline requires, cannot lower the minimum
maturity, and cannot switch off the signed-evidence requirement.

Example. With the `baseline` or `standard` profile, this file adds AGC-023,
keeps every other mandatory control at maturity 2, and leaves AGC-001 at its
per-control minimum of 1, so a declared owner still meets AGC-001. To demand
more for AGC-001, add `control_min_maturity: {AGC-001: 3}`.

```yaml
name: org-baseline
version: "2.1"
description: Organization baseline for all agent repositories.
mandatory_controls:
  - AGC-008
  - AGC-022
  - AGC-023
min_maturity: 2
require_signed_evidence: false
review_workflow: false
```

## Exceptions

Both kinds of exception need `control`, `reason` (10 characters or more), and
`approved_by`. `expires` is optional. An exception is valid through the end of
its expiry date (UTC). After that the engine ignores it and says so in the
status reason. An exception with a blank reason, a blank approver, or an
invalid date is ignored as well. One control can have only one exception.

```yaml
policy:
  not_applicable:
    - control: AGC-016
      reason: "Single agent. It does not exchange messages with other agents."
      approved_by: governance-review-board
      expires: "2027-06-30"
  accepted_risks:
    - control: AGC-021
      reason: "Red-team exercise is scheduled for the next quarter."
      approved_by: chief-information-security-officer
      expires: "2027-03-31"
```

| | `not_applicable` | `accepted_risks` |
| --- | --- | --- |
| Status | `not-applicable`, basis `approved` | `accepted-risk` |
| Score | Leaves the denominator | Stays in the denominator at maturity 0 |
| On a mandatory control | Meets the policy | `REVIEW_REQUIRED`, reason `mandatory-accepted-risk` |
| Hides a violation or a collector error | No | No |
| Shown in reports | Yes, with reason and approver | Yes, with reason and approver |

The scanner records who the file says approved the exception. It cannot
verify that the approval happened. Because the configuration lives in the
repository, treat a change to an exception like a change to code: require
review, and use an organization baseline for controls that must never be
waived. A violation or a critical finding blocks whatever exceptions exist.

Not-applicable without an exception: a capability-mode control with no
detected and no declared capability is `not-applicable` with the basis
`inferred`. On a mandatory control this gives `REVIEW_REQUIRED` with the
reason `mandatory-not-applicable-inferred`, so a person confirms the
inference.

## Decision reason codes

| Code | Outcome | Meaning |
| --- | --- | --- |
| `mandatory-control-failed` | `BLOCK` | A mandatory control has a violation or a failed test. |
| `mandatory-control-error` | `BLOCK` | A collector failed on a mandatory control. |
| `mandatory-evidence-invalid` | `BLOCK` | A mandatory control falls short, and its evidence was expired, bound to another commit or to changed files, unbound, malformed, or had a bad signature. |
| `critical-finding` | `BLOCK` | A finding of critical severity is open, on any control. |
| `mandatory-control-missing` | `BLOCK` (or `REVIEW_REQUIRED` with a review workflow) | A detector looked and found no mechanism. |
| `mandatory-control-unknown` | `BLOCK` (or `REVIEW_REQUIRED` with a review workflow) | The control could not be assessed. |
| `mandatory-below-min-maturity` | `BLOCK` (or `REVIEW_REQUIRED` with a review workflow) | The control is verified below the required level. The message says when unsigned evidence is the cause. |
| `mandatory-accepted-risk` | `REVIEW_REQUIRED` | A mandatory control has an accepted risk. |
| `mandatory-not-applicable-inferred` | `REVIEW_REQUIRED` | A mandatory control was treated as not applicable by inference. |
| `review-workflow` | `REVIEW_REQUIRED` | The profile turned one or more shortfalls into review items. |
| `no-agent-detected` | `REVIEW_REQUIRED` | No agent was found. Nothing was assessed. This is not a pass. |
| `policy-satisfied` | `ALLOW` | Every mandatory control meets the profile, and no critical finding is open. This is a policy decision, not a certification. |
| `policy-input-invalid` | `BLOCK` | Internal error: the engine had no catalog or no profile. |

The most restrictive reason decides: any `BLOCK` reason gives `BLOCK`,
otherwise any `REVIEW_REQUIRED` reason gives `REVIEW_REQUIRED`, otherwise the
outcome is `ALLOW`. The numeric score is never part of the decision.

## Programming interface

```go
// internal/controls
func Load() (*model.Catalog, error)
func Find(cat *model.Catalog, id string) (model.Control, bool)
func Domains(cat *model.Catalog) []DomainGroup

// internal/config
func Load(root, explicitPath string) (*Config, []string, error)
func Validate(data []byte) []string

// internal/policy
func ProfileNames() []string
func LoadProfile(name string) (*model.Profile, error)
func LoadBaseline(path string) (*model.Profile, error)
func Effective(base *model.Profile, cfg *config.Config, baseline *model.Profile) *model.Profile
func SelectProfileName(flag string, cfg *config.Config, agents []model.Agent) (name, source string)
func ProfileRank(name string) int                        // baseline 1, standard 2, high-risk 3, unknown 0
func RequiredMaturity(p *model.Profile, id string) int   // per-control minimum, else min_maturity
func Evaluate(in Input) ([]model.AgentAssessment, model.Score, model.Decision)
func AttachMappings(findings []model.Finding, cat *model.Catalog)
```

`config.Load` returns `(nil, nil, nil)` when no configuration file exists.
