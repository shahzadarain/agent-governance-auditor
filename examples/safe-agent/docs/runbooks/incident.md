# Incident runbook: ticket-triage-agent

Use this runbook when the agent does something it should not: it changes the
wrong tickets, tries tools it is not allowed to use, or cannot be explained
from its traces.

## Owner

- Owning team: support-engineering
- Accountable person: the support-engineering lead on duty

## Escalation

1. The person who notices the problem tells the support-engineering on-call.
2. On-call engages the kill switch first (see Containment), then investigates.
3. If user data may have been exposed or changed, on-call informs the security
   team and the data protection contact the same day.

## Containment

1. Engage the kill switch: create the file named by `TICKET_AGENT_KILL_FILE`
   (in Kubernetes, set the `KILL` key in the `ticket-triage-agent-control`
   config map). The agent checks it before every model call and tool call.
2. Confirm the stop: the trace shows no `tool-completed` record after the
   time the file appeared.
3. Scale the deployment to zero if the agent does not stop.

## Revocation

1. Rotate the approval signing key (`approval-key` in the
   `ticket-triage-agent` secret). Outstanding approvals stop verifying.
2. Revoke the service account token by deleting and re-creating the
   `ticket-triage-agent` service account.
3. Rotate the model API credential if the hosted model client is in use.

## Evidence preservation

1. Copy the audit log and the trace records before any restart.
2. Run `AuditLog.verify()` on the copy and record the result.
3. Record the commit SHA and image tag that were running.

## Recovery

1. Use the audit log to list the tickets the agent changed during the incident.
2. Reopen wrongly closed tickets with the operator-only compensation
   handler `reopen_ticket_compensation`.
3. Fix the cause, run `python tools/run_governance_tests.py`, and attach the
   new evidence file to the change.
4. Remove the kill file only after the owner approves the restart.

## Exercise history

No exercise has been recorded yet. Record each exercise here with the date,
the participants, and the time it took to stop the agent.
