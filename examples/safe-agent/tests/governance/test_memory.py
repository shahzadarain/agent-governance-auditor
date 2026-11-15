"""AGC-015: memory is isolated per user and tenant, and validated before storage."""

import unittest

from triage_agent.memory import MemoryRejected
from triage_agent.session import Session

from .support import ALICE, BOB, AgentTestCase


class MemoryTest(AgentTestCase):
    def remember_as(self, session, key, value):
        agent = self.make_agent([{"tool": "remember_preference", "arguments": {"key": key, "value": value}},
                                 {"final": "ok"}], session=session)
        return agent.run("remember this")

    def test_memory_is_isolated_between_users(self):
        self.remember_as(ALICE, "language", "French")
        self.assertEqual(self.memory.recall(ALICE, "language"), "French")
        self.assertIsNone(self.memory.recall(BOB, "language"))

    def test_same_key_does_not_collide_across_users(self):
        self.remember_as(ALICE, "language", "French")
        self.remember_as(BOB, "language", "German")
        self.assertEqual(self.memory.recall(ALICE, "language"), "French")
        self.assertEqual(self.memory.recall(BOB, "language"), "German")

    def test_memory_is_isolated_between_tenants(self):
        other_tenant = Session(user_id="alice", tenant="other", roles=frozenset({"support"}))
        self.remember_as(ALICE, "language", "French")
        self.assertIsNone(self.memory.recall(other_tenant, "language"))

    def test_oversized_value_is_rejected_before_storage(self):
        with self.assertRaises(PermissionError):
            # The policy denies arguments longer than the rule allows.
            self.remember_as(ALICE, "note", "x" * 501)
        self.assertIsNone(self.memory.recall(ALICE, "note"))

    def test_store_rejects_invalid_values_directly(self):
        for bad in ("x" * 501, "bell\x07", 42):
            with self.assertRaises(MemoryRejected):
                self.memory.remember(ALICE, "k", bad)
        self.assertIsNone(self.memory.recall(ALICE, "k"))


if __name__ == "__main__":
    unittest.main()
