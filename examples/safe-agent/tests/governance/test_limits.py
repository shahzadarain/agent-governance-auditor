"""AGC-012: the run stops when a step, token, or time limit is reached."""

import unittest
from unittest import mock

from triage_agent.limits import LimitExceeded, Limits

from .support import AgentTestCase

SEARCH = {"tool": "search_tickets", "arguments": {"text": "Printer"}, "tokens": 10}


class LimitsTest(AgentTestCase):
    def test_step_budget_exceeded_stops_the_run(self):
        agent = self.make_agent([dict(SEARCH) for _ in range(50)], limits=Limits(max_steps=3))
        with self.assertRaises(LimitExceeded):
            agent.run("loop forever")
        self.assertEqual(agent.tools_executed, 3)
        self.assertEqual(agent.model.calls, 3)

    def test_token_budget_exceeded_stops_before_the_tool_runs(self):
        agent = self.make_agent([dict(SEARCH, tokens=600), dict(SEARCH, tokens=600)], limits=Limits(max_tokens=1000))
        with self.assertRaises(LimitExceeded):
            agent.run("spend tokens")
        self.assertEqual(agent.tools_executed, 1)

    def test_time_limit_stops_the_run(self):
        agent = self.make_agent([dict(SEARCH) for _ in range(5)], limits=Limits(max_seconds=5.0))
        ticks = iter([0.0, 1.0, 2.0, 99.0, 100.0, 101.0])
        with mock.patch("triage_agent.agent.time.monotonic", lambda: next(ticks)):
            with self.assertRaises(LimitExceeded):
                agent.run("take too long")
        self.assertEqual(agent.tools_executed, 2)

    def test_run_within_limits_finishes(self):
        agent = self.make_agent([dict(SEARCH), {"final": "ok"}])
        self.assertEqual(agent.run("one search"), "ok")


if __name__ == "__main__":
    unittest.main()
