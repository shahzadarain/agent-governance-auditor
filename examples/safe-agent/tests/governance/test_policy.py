"""AGC-009: the policy decides before a tool runs, and errors mean deny."""

import unittest

from triage_agent import policy
from triage_agent.agent import PolicyDenied

from .support import VIEWER, AgentTestCase


class PolicyTest(AgentTestCase):
    def test_role_without_permission_is_denied(self):
        agent = self.make_agent([{"tool": "add_note", "arguments": {"ticket_id": "T-1", "note": "x",
                                                                  "idempotency_key": "k1"}}], session=VIEWER)
        with self.assertRaises(PolicyDenied):
            agent.run("add a note")
        self.assertEqual(agent.tools_executed, 0)

    def test_policy_engine_error_means_deny(self):
        def broken(session, tool, arguments):
            raise RuntimeError("policy backend unavailable")

        agent = self.make_agent([{"tool": "search_tickets", "arguments": {"text": "Printer"}}])
        agent.policy_evaluator = broken
        with self.assertRaises(PolicyDenied):
            agent.run("search")
        self.assertEqual(agent.tools_executed, 0)

    def test_policy_engine_returning_nothing_means_deny(self):
        agent = self.make_agent([{"tool": "search_tickets", "arguments": {"text": "Printer"}}])
        agent.policy_evaluator = lambda session, tool, arguments: None
        with self.assertRaises(PolicyDenied):
            agent.run("search")

    def test_tool_without_a_rule_is_denied(self):
        decision = policy.decide(VIEWER, "unknown_tool", {})
        self.assertFalse(decision.allowed)

    def test_permitted_call_is_allowed(self):
        decision = policy.decide(VIEWER, "search_tickets", {"text": "x"})
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.requires_approval)


if __name__ == "__main__":
    unittest.main()
