"""AGC-005: a tool that is not on the allowlist is rejected at dispatch."""

import unittest

from triage_agent import tools
from triage_agent.agent import ToolDenied

from .support import AgentTestCase


class AllowlistTest(AgentTestCase):
    def test_tool_outside_allowlist_is_rejected(self):
        agent = self.make_agent([{"tool": "delete_all_tickets", "arguments": {}}])
        with self.assertRaises(ToolDenied):
            agent.run("delete everything")
        self.assertEqual(agent.tools_executed, 0)

    def test_real_function_that_is_not_a_tool_is_rejected(self):
        # The compensation handler exists in the tools module but is not allowlisted.
        self.assertTrue(callable(tools.reopen_ticket_compensation))
        agent = self.make_agent([{"tool": "reopen_ticket_compensation",
                                  "arguments": {"ticket_id": "T-1", "idempotency_key": "k"}}])
        with self.assertRaises(ToolDenied):
            agent.run("reopen")
        self.assertEqual(agent.tools_executed, 0)

    def test_denied_call_is_audited(self):
        agent = self.make_agent([{"tool": "os.system", "arguments": {}}])
        with self.assertRaises(ToolDenied):
            agent.run("run a command")
        events = [r["event"]["event"] for r in agent.audit._read()]
        self.assertIn("tool-denied", events)

    def test_allowlisted_tool_runs(self):
        agent = self.make_agent([{"tool": "search_tickets", "arguments": {"text": "Printer"}}, {"final": "ok"}])
        self.assertEqual(agent.run("find printer"), "ok")
        self.assertEqual(agent.tools_executed, 1)


if __name__ == "__main__":
    unittest.main()
