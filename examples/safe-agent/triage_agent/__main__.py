"""Offline demo: python -m triage_agent

Runs one scripted task against an in-memory database. No network is used.
"""

import os
import tempfile

from .agent import Agent
from .approval import ApprovalService
from .audit import AuditLog
from .data import open_database, seed_demo
from .killswitch import KillSwitch
from .llm import ScriptedModel
from .memory import MemoryStore
from .session import Session
from .tracing import Tracer


def main():
    workdir = tempfile.mkdtemp(prefix="triage-agent-")
    db = open_database()
    seed_demo(db)
    model = ScriptedModel([
        {"tool": "search_tickets", "arguments": {"text": "Printer"}, "tokens": 40},
        {"tool": "add_note", "arguments": {"ticket_id": "T-1", "note": "Asked facilities to check the printer.",
                                           "idempotency_key": "demo-note-1"}, "tokens": 55},
        {"final": "I found the printer ticket and added a note.", "tokens": 20},
    ])
    agent = Agent(
        model=model,
        session=Session(user_id="alice", roles=frozenset({"support"})),
        db=db,
        memory=MemoryStore(),
        kill_switch=KillSwitch(os.path.join(workdir, "KILL")),
        approvals=ApprovalService(os.urandom(32)),
        audit=AuditLog(os.path.join(workdir, "audit.jsonl")),
        tracer=Tracer(),
    )
    print(agent.run("Find my printer ticket and add a note."))
    print("audit records verified:", agent.audit.verify())
    print("trace records:", len(agent.tracer.records))


if __name__ == "__main__":
    main()
