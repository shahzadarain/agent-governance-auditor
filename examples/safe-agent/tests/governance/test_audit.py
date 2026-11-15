"""AGC-023: altering, removing, or reordering audit records is detected."""

import json
import unittest

from triage_agent.audit import AuditLog, AuditTamperError

from .support import AgentTestCase


class AuditTest(AgentTestCase):
    def filled_log(self):
        log = AuditLog(self.audit_path)
        for n in range(4):
            log.append({"event": "tool-executed", "tool": "search_tickets", "n": n})
        return log

    def rewrite(self, mutate):
        with open(self.audit_path, "r", encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle]
        records = mutate(records)
        with open(self.audit_path, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    def test_untouched_log_verifies(self):
        self.assertEqual(self.filled_log().verify(), 4)

    def test_altered_record_is_detected(self):
        log = self.filled_log()

        def mutate(records):
            records[1]["event"]["tool"] = "close_ticket"
            return records

        self.rewrite(mutate)
        with self.assertRaises(AuditTamperError):
            log.verify()

    def test_removed_record_is_detected(self):
        log = self.filled_log()
        self.rewrite(lambda records: records[:1] + records[2:])
        with self.assertRaises(AuditTamperError):
            log.verify()

    def test_reordered_records_are_detected(self):
        log = self.filled_log()
        self.rewrite(lambda records: [records[0], records[2], records[1], records[3]])
        with self.assertRaises(AuditTamperError):
            log.verify()

    def test_chain_continues_after_reopen(self):
        self.filled_log()
        reopened = AuditLog(self.audit_path)
        reopened.append({"event": "run-finished"})
        self.assertEqual(reopened.verify(), 5)

    def test_agent_actions_are_recorded(self):
        agent = self.make_agent([{"tool": "search_tickets", "arguments": {"text": "Printer"}}, {"final": "ok"}])
        agent.run("search")
        self.assertEqual(agent.audit.verify(), 2)


if __name__ == "__main__":
    unittest.main()
