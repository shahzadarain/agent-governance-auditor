"""AGC-010: closing a ticket needs a valid, bound, unused human approval."""

import dataclasses
import unittest

from triage_agent.approval import ApprovalError

from .support import AgentTestCase

ARGS = {"ticket_id": "T-1", "idempotency_key": "close-1"}
CLOSE = [{"tool": "close_ticket", "arguments": dict(ARGS)}, {"final": "closed"}]


class ApprovalTest(AgentTestCase):
    def approve(self, **overrides):
        fields = dict(actor="alice", approver="carol", action="close_ticket", params=dict(ARGS), approved=True)
        fields.update(overrides)
        return self.approvals.record_decision(**fields)

    def assert_rejected(self, agent, message):
        with self.assertRaises(ApprovalError) as raised:
            agent.run("close T-1")
        self.assertIn(message, str(raised.exception))
        self.assertEqual(self.ticket_status("T-1"), "open")
        self.assertEqual(agent.tools_executed, 0)

    def test_missing_approval_is_rejected(self):
        self.assert_rejected(self.make_agent(CLOSE), "missing")

    def test_valid_approval_allows_the_action(self):
        agent = self.make_agent(CLOSE)
        agent.submit_approval("close_ticket", self.approve())
        self.assertEqual(agent.run("close T-1"), "closed")
        self.assertEqual(self.ticket_status("T-1"), "closed")

    def test_expired_approval_is_rejected(self):
        agent = self.make_agent(CLOSE)
        agent.submit_approval("close_ticket", self.approve(ttl_seconds=60))
        self.clock.now += 61
        self.assert_rejected(agent, "expired")

    def test_tampered_approval_is_rejected(self):
        agent = self.make_agent(CLOSE)
        token = dataclasses.replace(self.approve(), expires_at=self.clock.now + 10_000)
        agent.submit_approval("close_ticket", token)
        self.assert_rejected(agent, "signature")

    def test_denied_decision_cannot_be_flipped(self):
        agent = self.make_agent(CLOSE)
        token = dataclasses.replace(self.approve(approved=False), decision="approved")
        agent.submit_approval("close_ticket", token)
        self.assert_rejected(agent, "signature")

    def test_denied_approval_is_rejected(self):
        agent = self.make_agent(CLOSE)
        agent.submit_approval("close_ticket", self.approve(approved=False))
        self.assert_rejected(agent, "denied")

    def test_approval_for_other_parameters_is_rejected(self):
        agent = self.make_agent(CLOSE)
        agent.submit_approval("close_ticket", self.approve(params={"ticket_id": "T-2", "idempotency_key": "close-1"}))
        self.assert_rejected(agent, "different parameters")

    def test_approval_for_another_actor_is_rejected(self):
        agent = self.make_agent(CLOSE)
        agent.submit_approval("close_ticket", self.approve(actor="bob"))
        self.assert_rejected(agent, "different actor")

    def test_replayed_approval_is_rejected(self):
        token = self.approve()
        first = self.make_agent(CLOSE)
        first.submit_approval("close_ticket", token)
        self.assertEqual(first.run("close T-1"), "closed")
        self.db.execute("UPDATE tickets SET status = ? WHERE id = ?", ("open", "T-1"))
        second = self.make_agent(CLOSE)
        second.submit_approval("close_ticket", token)
        self.assert_rejected(second, "already used")

    def test_token_signed_with_another_key_is_rejected(self):
        from triage_agent.approval import ApprovalService

        forged = ApprovalService(b"attacker-key", clock=self.clock).record_decision(
            actor="alice", approver="carol", action="close_ticket", params=dict(ARGS), approved=True)
        agent = self.make_agent(CLOSE)
        agent.submit_approval("close_ticket", forged)
        self.assert_rejected(agent, "signature")


if __name__ == "__main__":
    unittest.main()
