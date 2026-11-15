"""AGC-018: a repeated mutating request is applied once, and can be compensated."""

import unittest

from triage_agent import data, tools

from .support import ALICE, AgentTestCase

NOTE = {"tool": "add_note", "arguments": {"ticket_id": "T-1", "note": "checked", "idempotency_key": "note-1"}}


class IdempotencyTest(AgentTestCase):
    def test_repeated_request_is_applied_once(self):
        agent = self.make_agent([dict(NOTE), dict(NOTE), {"final": "ok"}])
        agent.run("add the note twice")
        self.assertEqual(data.count_notes(self.db, "alice", "T-1"), 1)

    def test_different_keys_are_separate_requests(self):
        second = {"tool": "add_note", "arguments": dict(NOTE["arguments"], idempotency_key="note-2")}
        agent = self.make_agent([dict(NOTE), second, {"final": "ok"}])
        agent.run("add two notes")
        self.assertEqual(data.count_notes(self.db, "alice", "T-1"), 2)

    def test_failed_write_leaves_no_partial_state(self):
        self.db.execute("DROP TABLE idempotency")
        with self.assertRaises(Exception):
            data.insert_note(self.db, "alice", "T-1", "half", "note-9")
        self.db.executescript(data.SCHEMA)
        self.assertEqual(data.count_notes(self.db, "alice", "T-1"), 0)

    def test_close_can_be_compensated(self):
        context = tools.ToolContext(session=ALICE, db=self.db, memory=self.memory)
        tools.close_ticket(context, "T-1", "close-1")
        self.assertEqual(self.ticket_status("T-1"), "closed")
        tools.reopen_ticket_compensation(context, "T-1", "reopen-1")
        self.assertEqual(self.ticket_status("T-1"), "open")


if __name__ == "__main__":
    unittest.main()
