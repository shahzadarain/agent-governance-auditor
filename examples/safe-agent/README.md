# Safe agent (reference example)

A small "ticket-triage-agent" with real, working governance controls. It uses
the Python standard library only and runs offline against a scripted model.
The enforcement code is real, and the tests in `tests/governance/` exercise
that code.

It is a reference for the control patterns. It is not a production system:
there is no web service, no real identity provider, and no hosted model in
the default run.

## Run it

```sh
python -m triage_agent                  # offline demo
python tools/run_governance_tests.py    # run the tests and write the evidence file
agentgov scan .                         # scan it
```

On Windows PowerShell the same commands work unchanged.

## Where each control lives

| Control | What the code does | File |
| --- | --- | --- |
| AGC-005 Allowlisted tool access | One dispatch point rejects any tool name that is not in `ALLOWED_TOOLS` | `triage_agent/agent.py`, `triage_agent/tools.py` |
| AGC-007 User-enforced data layer | Identity comes from the session; every query filters by owner; SQL is parameterized | `triage_agent/data.py` |
| AGC-008 Vault-injected secrets | Secrets are read from a mounted file or injected variable; none is written in code | `triage_agent/secret_store.py`, `deploy/k8s.yaml` |
| AGC-009 External policy engine | A deterministic policy module decides before a tool runs; errors mean deny | `triage_agent/policy.py` |
| AGC-010 Human approval gates | HMAC-signed approval bound to actor, action, parameter digest, expiry, and a single-use nonce | `triage_agent/approval.py` |
| AGC-011 Content guardrails | Arguments are checked against the tool schema; tool results reach the model as bounded data | `triage_agent/guards.py` |
| AGC-012 Resource limits | Step, time, and token limits checked inside the loop | `triage_agent/agent.py`, `triage_agent/limits.py` |
| AGC-013 Sandbox | Non-root, read-only container with all capabilities dropped | `Dockerfile`, `compose.yaml`, `deploy/k8s.yaml` |
| AGC-015 Memory integrity | Memory is keyed by tenant and user and validated before storage | `triage_agent/memory.py` |
| AGC-017 Kill switch | A kill file is re-read before every model call and tool call | `triage_agent/killswitch.py` |
| AGC-018 Reversible actions | Idempotency keys, transactions, and a compensation handler | `triage_agent/data.py`, `triage_agent/tools.py` |
| AGC-019 Incident runbook | Owner, escalation, containment, revocation, recovery | `docs/runbooks/incident.md` |
| AGC-022 Step tracing | Structured records with run IDs, span links, and redaction | `triage_agent/tracing.py` |
| AGC-023 Tamper-evident audit trail | Hash-chained log with verification | `triage_agent/audit.py` |
| AGC-024 Monitoring | Alert rules on agent signals (static rules only) | `monitoring/alerts.yaml` |

## Evidence

`tools/run_governance_tests.py` runs the test suite. For each control it
writes one item to `.agentgov/evidence/governance-tests.json`:

- If every test for the control passed, the item says `present` and `pass`.
- If any test failed, the item says `violation` and `fail`.

Each item is bound to the content of the implementation and test files. If
you change one of those files, the scanner reports a digest mismatch and
stops counting the item until you run the tests again. Items expire after 90
days. The file is unsigned.

## What this example does not show

- Operational evidence. Nothing here proves how a deployed copy behaves.
- A real identity provider. `deploy/k8s.yaml` shows the intended workload
  identity; it has not been applied to a cluster.
- Token issuance (AGC-006) and inter-agent messaging (AGC-016).
- Metrics export. The alert rules assume a log-to-metrics exporter.
