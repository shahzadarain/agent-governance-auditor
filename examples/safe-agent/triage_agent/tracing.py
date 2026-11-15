"""Structured step tracing with run IDs and redaction.

Every step and every tool call becomes one record that carries the run ID.
A tool call records the span of the step that asked for it, so the two can be
joined. Sensitive values are redacted before a record is stored.
"""

import json
import time
import uuid

SENSITIVE_KEYS = ("password", "secret", "token", "api_key", "authorization", "note", "value")
REDACTED = "[redacted]"


def redact(detail):
    if isinstance(detail, dict):
        return {k: (REDACTED if any(s in k.lower() for s in SENSITIVE_KEYS) else redact(v)) for k, v in detail.items()}
    if isinstance(detail, (list, tuple)):
        return [redact(v) for v in detail]
    if isinstance(detail, str) and len(detail) > 200:
        return detail[:200] + "...[truncated]"
    return detail


class Tracer:
    def __init__(self, sink=None, clock=time.time):
        self.records = []
        self._sink = sink
        self._clock = clock

    def new_run(self):
        return uuid.uuid4().hex

    def record_step(self, run_id, step, event, *, tool_name=None, parent_span=None, actor=None, detail=None):
        span_id = uuid.uuid4().hex[:16]
        record = {
            "run_id": run_id,
            "span_id": span_id,
            "parent_span": parent_span,
            "step": step,
            "event": event,
            "tool": tool_name,
            "actor": actor,
            "detail": redact(detail),
            "ts": self._clock(),
        }
        self.records.append(record)
        if self._sink is not None:
            self._sink.write(json.dumps(record, sort_keys=True) + "\n")
        return span_id
