"""Hash-chained audit log.

Each record stores the hash of the record before it. Changing, removing, or
reordering any record breaks the chain, and verify() reports it.
"""

import hashlib
import json
import os
import time

GENESIS = "0" * 64


class AuditTamperError(RuntimeError):
    pass


def _record_hash(body):
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class AuditLog:
    def __init__(self, path, clock=time.time):
        self.path = path
        self._clock = clock
        self._seq = 0
        self._last_hash = GENESIS
        if os.path.exists(path):
            for record in self._read():
                self._seq = record["seq"]
                self._last_hash = record["hash"]

    def _read(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def append(self, event):
        prev_hash = self._last_hash
        body = {"seq": self._seq + 1, "ts": self._clock(), "event": event, "prev_hash": prev_hash}
        record = dict(body, hash=_record_hash(body))
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self._seq = record["seq"]
        self._last_hash = record["hash"]
        return record

    def verify(self):
        """Return the number of records, or raise AuditTamperError."""
        prev_hash = GENESIS
        count = 0
        for record in self._read():
            body = {k: record[k] for k in ("seq", "ts", "event", "prev_hash")}
            if record["prev_hash"] != prev_hash or record["seq"] != count + 1:
                raise AuditTamperError("audit chain is broken at record %d" % (count + 1))
            if _record_hash(body) != record["hash"]:
                raise AuditTamperError("audit record %d was altered" % (count + 1))
            prev_hash = record["hash"]
            count += 1
        return count
