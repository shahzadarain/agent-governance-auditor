"""AGC-022: a step and its tool call share a run ID and are linked, with redaction."""

import io
import json
import unittest

from triage_agent.tracing import REDACTED, Tracer

from .support import AgentTestCase


class TracingTest(AgentTestCase):
    def test_step_and_tool_call_are_correlated(self):
        agent = self.make_agent([{"tool": "search_tickets", "arguments": {"text": "Printer"}}, {"final": "ok"}])
        agent.run("search")
        records = agent.tracer.records
        self.assertEqual(len({r["run_id"] for r in records}), 1)
        step = next(r for r in records if r["event"] == "model-step" and r["step"] == 0)
        requested = next(r for r in records if r["event"] == "tool-requested")
        completed = next(r for r in records if r["event"] == "tool-completed")
        self.assertEqual(requested["parent_span"], step["span_id"])
        self.assertEqual(completed["parent_span"], step["span_id"])
        self.assertEqual(requested["tool"], "search_tickets")
        self.assertEqual(requested["actor"], "alice")

    def test_two_runs_have_different_run_ids(self):
        agent = self.make_agent([{"final": "a"}])
        agent.run("one")
        first = {r["run_id"] for r in agent.tracer.records}
        agent.model._actions = [{"final": "b"}]
        agent.run("two")
        self.assertEqual(len({r["run_id"] for r in agent.tracer.records}), 2)
        self.assertEqual(len(first), 1)

    def test_sensitive_arguments_are_redacted(self):
        agent = self.make_agent([{"tool": "add_note", "arguments": {"ticket_id": "T-1", "note": "card 4111 1111",
                                                                  "idempotency_key": "k1"}}, {"final": "ok"}])
        agent.run("add note")
        requested = next(r for r in agent.tracer.records if r["event"] == "tool-requested")
        self.assertEqual(requested["detail"]["note"], REDACTED)
        self.assertNotIn("4111", json.dumps(agent.tracer.records))

    def test_denied_tool_request_is_still_traced(self):
        agent = self.make_agent([{"tool": "not_a_tool", "arguments": {}}])
        with self.assertRaises(PermissionError):
            agent.run("bad tool")
        self.assertTrue(any(r["event"] == "tool-requested" and r["tool"] == "not_a_tool" for r in agent.tracer.records))

    def test_records_are_written_to_the_sink_as_json_lines(self):
        sink = io.StringIO()
        tracer = Tracer(sink=sink)
        run_id = tracer.new_run()
        tracer.record_step(run_id, 0, "tool-requested", tool_name="get_ticket", detail={"token": "abc"})
        line = json.loads(sink.getvalue())
        self.assertEqual(line["run_id"], run_id)
        self.assertEqual(line["detail"]["token"], REDACTED)


if __name__ == "__main__":
    unittest.main()
