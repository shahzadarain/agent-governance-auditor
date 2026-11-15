"""Shared builders for the governance tests. Everything is local and synthetic."""

import os
import shutil
import tempfile
import unittest

from triage_agent.agent import Agent
from triage_agent.approval import ApprovalService
from triage_agent.audit import AuditLog
from triage_agent.data import open_database, seed_demo
from triage_agent.killswitch import KillSwitch
from triage_agent.limits import Limits
from triage_agent.llm import ScriptedModel
from triage_agent.memory import MemoryStore
from triage_agent.session import Session
from triage_agent.tracing import Tracer

TEST_SIGNING_KEY = b"synthetic-test-key-not-a-secret"

ALICE = Session(user_id="alice", roles=frozenset({"support"}))
BOB = Session(user_id="bob", roles=frozenset({"support"}))
VIEWER = Session(user_id="alice", roles=frozenset({"viewer"}))


class FakeClock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class AgentTestCase(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="triage-agent-test-")
        self.addCleanup(shutil.rmtree, self.workdir, True)
        self.db = open_database()
        seed_demo(self.db)
        self.addCleanup(self.db.close)
        self.clock = FakeClock()
        self.kill_path = os.path.join(self.workdir, "KILL")
        self.audit_path = os.path.join(self.workdir, "audit.jsonl")
        self.memory = MemoryStore()
        self.approvals = ApprovalService(TEST_SIGNING_KEY, clock=self.clock)

    def make_agent(self, actions, session=ALICE, limits=None, on_call=None):
        return Agent(
            model=ScriptedModel(actions, on_call=on_call),
            session=session,
            db=self.db,
            memory=self.memory,
            kill_switch=KillSwitch(self.kill_path),
            approvals=self.approvals,
            audit=AuditLog(self.audit_path),
            tracer=Tracer(),
            limits=limits or Limits(),
        )

    def ticket_status(self, ticket_id):
        row = self.db.execute("SELECT status FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        return row[0]
