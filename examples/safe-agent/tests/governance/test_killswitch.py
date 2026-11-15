"""AGC-017: after the kill switch is engaged, no further action runs."""

import unittest

from triage_agent.killswitch import AgentKilled

from .support import AgentTestCase

SEARCH = {"tool": "search_tickets", "arguments": {"text": "Printer"}}


class KillSwitchTest(AgentTestCase):
    def engage(self):
        with open(self.kill_path, "w", encoding="utf-8") as handle:
            handle.write("stop")

    def test_engaged_switch_blocks_the_first_action(self):
        self.engage()
        agent = self.make_agent([dict(SEARCH)])
        with self.assertRaises(AgentKilled):
            agent.run("search")
        self.assertEqual(agent.model.calls, 0)
        self.assertEqual(agent.tools_executed, 0)

    def test_switch_engaged_mid_run_stops_within_one_step(self):
        # The operator engages the switch while the model is "thinking" on call 3.
        def on_call(call_number):
            if call_number == 3:
                self.engage()

        agent = self.make_agent([dict(SEARCH) for _ in range(6)], on_call=on_call)
        with self.assertRaises(AgentKilled):
            agent.run("keep searching")
        # Two tools ran before the switch. The tool requested during call 3 never ran.
        self.assertEqual(agent.tools_executed, 2)
        self.assertEqual(agent.model.calls, 3)

    def test_direct_dispatch_is_blocked_too(self):
        agent = self.make_agent([])
        self.engage()
        with self.assertRaises(AgentKilled):
            agent.dispatch("run-1", 0, "search_tickets", {"text": "Printer"})
        self.assertEqual(agent.tools_executed, 0)


if __name__ == "__main__":
    unittest.main()
