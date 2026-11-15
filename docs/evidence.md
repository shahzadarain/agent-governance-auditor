# Evidence

A scan that reads code can show that a control is implemented. It cannot show that the control was tested or that it works in operation. That proof comes from evidence files, which your tests or your running system write and the scan reads.

This page explains the three kinds of evidence, the file format, how evidence is tied to your code, and how to sign it.

## Contents

- [Three kinds of evidence](#three-kinds-of-evidence)
- [Where evidence files live](#where-evidence-files-live)
- [The file format](#the-file-format)
- [Binding to file content](#binding-to-file-content)
- [Expiry](#expiry)
- [Signing](#signing)
- [What makes evidence stop counting](#what-makes-evidence-stop-counting)
- [Writing your own evidence emitter](#writing-your-own-evidence-emitter)
- [Limits](#limits)

## Three kinds of evidence

| | Static evidence | Tested evidence | Runtime evidence |
| --- | --- | --- | --- |
| Who produces it | The scanner, when it reads your files | Your test run | Your running system, an external attestation, or a recorded manual review |
| `source_type` | `static` or `configuration` | `test` | `runtime`, `external-attestation`, or `manual-review` |
| Highest maturity it can support | 2 (implemented). For AGC-001, AGC-002, and AGC-019 it is 1 (declared). | 3 (tested) | 4 (verified in operation) |
| What it shows | The code or configuration for a control exists. | Tests that exercise the control passed for this exact content. | The control worked in a real environment. |
| What it does not show | That the code works or cannot be bypassed. | How a deployed agent behaves. | That it will keep working after the next change. |
| How you supply it | You do nothing. Run a scan. | A JSON file in `.agentgov/evidence/` | A JSON file in `.agentgov/evidence/` |
| Shipped support | Built in. | The safe example and the starter agent include a working emitter. | The file format accepts it. This release ships no runtime collector, so you write the file from your own system. |

The scanner never raises its own static evidence above the cap for the control. An evidence file cannot claim to be static or configuration evidence, and a file with `source_type` `test` cannot claim operational strength.

## Where evidence files live

By default the scan reads every `*.json` file directly inside `.agentgov/evidence/` in the scanned folder. Subfolders are not read. To use other folders, list them in `.agentgov.yaml`:

```yaml
verification:
  evidence_paths:
    - .agentgov/evidence
```

Each path must be inside the repository. A path that leaves the repository, or an evidence file that is a symbolic link, is ignored with a warning.

## The file format

An evidence file is one JSON object with a version and a list of items. This is the start of the real file in the safe example, [`examples/safe-agent/.agentgov/evidence/governance-tests.json`](../examples/safe-agent/.agentgov/evidence/governance-tests.json):

```json
{
  "schema_version": "1",
  "evidence": [
    {
      "control_id": "AGC-005",
      "agent_id": "ticket-triage-agent",
      "source_type": "test",
      "collector": "safe-agent.governance-tests",
      "observed_at": "2026-11-15T12:04:46Z",
      "valid_until": "2027-02-13T12:04:46Z",
      "result": "pass",
      "signal": "present",
      "strength": "tested",
      "summary": "4 governance tests passed (test_allowlist): a tool outside the allowlist is rejected at dispatch and never runs.",
      "limitations": [
        "The tests use a scripted model and synthetic data in one process. They do not show how a deployed agent behaves.",
        "The evidence is unsigned."
      ],
      "subject": {
        "paths": [
          "tests/governance/support.py",
          "tests/governance/test_allowlist.py",
          "triage_agent/agent.py",
          "triage_agent/tools.py"
        ],
        "digest": "198140e050f22d9234f79ee4c1bcab13993678000266bd2d09beb16d0a734271"
      },
      "identity_context": "local run of tools/run_governance_tests.py with Python 3.12"
    },
```

Fields of one item:

| Field | Required | Meaning |
| --- | --- | --- |
| `control_id` | yes | `AGC-001` to `AGC-024`. |
| `agent_id` | yes | The agent the evidence is about. `*` means every agent. |
| `source_type` | yes | `test`, `runtime`, `external-attestation`, or `manual-review`. |
| `collector` | yes | A name for the thing that produced the item. |
| `observed_at` | yes | When it was observed, as an RFC 3339 timestamp. |
| `result` | yes | `pass`, `fail`, or `inconclusive`. |
| `signal` | yes | `present`, `absent`, `violation`, `declared`, or `error`. |
| `strength` | yes | `declared`, `implementation`, `tested`, or `operational`. |
| `summary` | yes | One or two plain sentences. Shown in reports. |
| `valid_until` | no | When the evidence expires. |
| `limitations` | no | What the evidence does not show. Up to 20 entries. |
| `subject` | no | The files the evidence covers (`paths`) and their `digest`. |
| `commit_sha` | no | The full commit the evidence was produced from. |
| `identity_context` | no | Who or what ran the collection. |
| `signature` | no | Added by `agentgov evidence sign`. |

Rules the loader enforces:

- `result` and `signal` must agree. `present` needs `pass`. `violation` needs `fail`. Every other signal needs `inconclusive`.
- Unknown fields are rejected.
- A file may be at most 256 KiB and hold at most 500 items. At most 200 files are read from one folder.

The JSON Schema is in [`policies/schema/evidence.schema.json`](../policies/schema/evidence.schema.json).

A failing test matters too. An item with `signal` `violation` and `result` `fail` marks the control as failed, the same way a static violation does.

## Binding to file content

Evidence must be tied to the code it was produced from. Otherwise a test result from last month could vouch for code written today. An item can be bound in two ways, and it needs at least one of them:

- **Subject digest.** The item lists the files it covers and one SHA-256 digest computed over their paths and content. When the scan runs, it computes the digest again from the files on disk. If any listed file changed, the digests differ and the item stops counting.
- **Commit.** The item names the full commit SHA. The scan compares it with the commit of the repository.

An item with neither is marked "unbound" and gets no credit.

To compute a subject digest for a set of files:

```sh
agentgov evidence digest triage_agent/agent.py tests/governance/test_allowlist.py
```

It prints one line of 64 hexadecimal characters. Line endings are normalized before hashing, so the same file gives the same digest on Windows and on Linux.

You can see the binding work. In a starter agent with fresh evidence, add one comment line to `triage_agent/killswitch.py` and verify the evidence:

```text
$ agentgov evidence verify .agentgov/evidence/governance-tests.json
...
AGC-015  pass     validity=valid integrity=unsigned
AGC-017  pass     validity=digest-mismatch integrity=unsigned  (the subject files changed after the evidence was collected)
AGC-018  pass     validity=valid integrity=unsigned
...
agentgov: error: 1 evidence problem(s) found
```

The kill switch control (AGC-017) drops from "Verified by tests" back to "Implemented (not yet tested)" in the next scan. Run the tests again and it returns.

## Expiry

`valid_until` is optional. When it is present and in the past, the item is expired and gets no credit. When it is absent, the item does not expire by age. There is no built-in maximum age, so set `valid_until` in your emitter. The example emitter uses 90 days.

## Signing

Unsigned evidence in the repository can be written by anyone who can open a pull request. A signature shows that the evidence came from a holder of your signing key, for example your CI system.

Create a key pair once:

```sh
agentgov evidence keygen --out-dir ../keys
```

This writes `agentgov-evidence.key` (private) and `agentgov-evidence.pub` (public). Keep the private key in your CI secret store, outside the repository. Give the public key to whoever runs scans.

Sign an evidence file after your tests write it:

```sh
agentgov evidence sign .agentgov/evidence/governance-tests.json --key ../keys/agentgov-evidence.key
```

Check it, and scan with the public key:

```sh
agentgov evidence verify .agentgov/evidence/governance-tests.json --trust-key ../keys/agentgov-evidence.pub
agentgov scan . --profile high-risk --trust-key ../keys/agentgov-evidence.pub
```

Real output of the verify command on signed evidence:

```text
AGC-005  pass     validity=valid integrity=verified
AGC-007  pass     validity=valid integrity=verified
...
12 evidence item(s) are valid for the current content.
```

How signing affects credit:

| Profile | Unsigned test or runtime evidence | Signed and verified |
| --- | --- | --- |
| `baseline`, `standard` | Credited in full. | Credited in full. |
| `high-risk` | Credited only up to level 2 (implemented). | Credited in full. |

Two details to know:

- Once an item carries a signature, it must verify. A signed item scanned without the matching `--trust-key` is treated as invalid, not as unsigned. The message is "the item is signed, but no trusted key was supplied to verify it".
- The signature covers the content fields of the item, including the subject paths and digest. Changing any of them breaks the signature. The algorithm is Ed25519.

The effect on the score is visible in the starter agent. With the `high-risk` profile, unsigned evidence gives 45/100 and signed evidence gives 60/100. Both are still blocked, because that profile also requires controls that the tests do not cover.

## What makes evidence stop counting

| Reason shown | Cause | What to do |
| --- | --- | --- |
| `digest-mismatch` | A file listed in `subject.paths` changed, or cannot be read. | Run the tests again to produce fresh evidence. |
| `commit-mismatch` | The item names a different commit. | Produce the evidence from the commit you scan. |
| `expired` | `valid_until` has passed. | Run the collection again. |
| `unbound` | The item has neither a subject digest nor a commit. | Add one of them in your emitter. |
| `invalid-signature` | The signature does not match a trusted key, or no key was supplied. | Pass the right `--trust-key`, or sign again after regenerating. |
| `malformed` | The item breaks the schema or one of the rules above. | Fix the emitter. `agentgov evidence verify` names the problem. |

Evidence that stops counting is never deleted from the report. The control shows the level that the remaining valid evidence supports, and the reason is listed. When a mandatory control falls below its required level because its evidence is invalid, the decision is `BLOCK`.

## Writing your own evidence emitter

An emitter is a small script that runs your tests and writes the JSON file. The one in the safe example is about 180 lines of standard-library Python: [`examples/safe-agent/tools/run_governance_tests.py`](../examples/safe-agent/tools/run_governance_tests.py). Read it first. It does five things:

1. Keeps a table that maps each control to the test module that exercises it and to the implementation files those tests cover.
2. Runs the tests for each control.
3. Sets `signal` `present` and `result` `pass` when every test for the control passed. Sets `violation` and `fail` when any test failed, errored, or was skipped.
4. Computes the subject digest over the test files and the implementation files.
5. Writes the file with `observed_at`, a `valid_until` 90 days ahead, a summary, and honest limitations.

To write one for your own test framework:

- Map tests to controls by hand. Only claim a control when the tests try to break it: a call to a tool that is not allowed, a missing approval, a second user reading the first user's data. `agentgov explain <ID>` lists what level 3 needs for each control.
- Include both the test files and the implementation files in `subject.paths`, so a change to either invalidates the evidence.
- Compute the digest with `agentgov evidence digest <paths>` or with the same algorithm as the example script. The project has a test that keeps the two in agreement.
- Write the summary for a reader who was not there. Say how many tests ran and what they showed.
- Sign the file in CI if you use the `high-risk` profile.
- Check your output with `agentgov evidence verify <file>` before you rely on it.

### Evidence that does not come from tests

Some controls cannot be tested in code. Ownership (AGC-001) is one. For these you can record an attestation or a manual review. This item raises AGC-001 from "Declared only" to level 3 in a starter agent. It is bound to the configuration file, so it stops counting when the declaration changes:

```json
{
  "schema_version": "1",
  "evidence": [
    {
      "control_id": "AGC-001",
      "agent_id": "ticket-triage-agent",
      "source_type": "external-attestation",
      "collector": "owner-attestation",
      "observed_at": "2026-11-15T12:00:00Z",
      "valid_until": "2027-02-01T00:00:00Z",
      "result": "pass",
      "signal": "present",
      "strength": "tested",
      "summary": "The owning team confirmed ownership and the inventory entry in the service registry.",
      "subject": {
        "paths": [".agentgov.yaml"],
        "digest": "<output of: agentgov evidence digest .agentgov.yaml>"
      }
    }
  ]
}
```

The scanner cannot check that the attestation is true. It records who the collector says it is and shows the item in the report. Sign such files, and review them like any other change.

## Limits

- The scan does not run your tests. It trusts the evidence file to the extent that the binding, the expiry, and the signature allow. A person with the signing key can sign a false claim.
- Any trusted key can sign evidence for any control. There is no per-control or per-collector key.
- There is no replay counter. Protection against reuse of old evidence comes from the content binding and from `valid_until`.
- Under `baseline` and `standard`, unsigned evidence in the repository is credited. If pull request authors are not trusted, use a baseline file that requires signed evidence. See [policy-reference.md](policy-reference.md).
