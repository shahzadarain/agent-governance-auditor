"""AGC-007: one user cannot read or change another user's records."""

import unittest

from triage_agent import data
from triage_agent.guards import InvalidArguments

from .support import ALICE, BOB, AgentTestCase


class DataIsolationTest(AgentTestCase):
    def test_cross_user_read_is_rejected(self):
        # T-3 belongs to bob. Alice asks for it by ID.
        agent = self.make_agent([{"tool": "get_ticket", "arguments": {"ticket_id": "T-3"}}], session=ALICE)
        with self.assertRaises(data.NotFound):
            agent.run("show me T-3")

    def test_owner_can_read_own_ticket(self):
        agent = self.make_agent([{"tool": "get_ticket", "arguments": {"ticket_id": "T-3"}}, {"final": "ok"}], session=BOB)
        self.assertEqual(agent.run("show me T-3"), "ok")

    def test_search_returns_only_own_rows(self):
        rows = data.find_tickets(self.db, "alice", "")
        self.assertEqual(sorted(r["id"] for r in rows), ["T-1", "T-2"])

    def test_model_cannot_supply_an_identity(self):
        # The tool schema has no user_id argument, so the model cannot name another user.
        agent = self.make_agent([{"tool": "get_ticket", "arguments": {"ticket_id": "T-3", "user_id": "bob"}}])
        with self.assertRaises(InvalidArguments):
            agent.run("show me T-3 as bob")

    def test_cross_user_write_is_rejected(self):
        agent = self.make_agent([{"tool": "add_note", "arguments": {"ticket_id": "T-3", "note": "x",
                                                                  "idempotency_key": "k1"}}], session=ALICE)
        with self.assertRaises(data.NotFound):
            agent.run("annotate T-3")
        self.assertEqual(data.count_notes(self.db, "bob", "T-3"), 0)

    def test_sql_text_in_arguments_is_treated_as_data(self):
        rows = data.find_tickets(self.db, "alice", "x' OR '1'='1")
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
