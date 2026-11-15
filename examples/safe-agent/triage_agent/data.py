"""Data layer. Every query is filtered by the caller identity.

The identity is passed in by trusted code from the session. It never comes
from tool arguments. All SQL is parameterized.
"""

import json
import sqlite3


class NotFound(LookupError):
    """Raised for missing rows and for rows owned by someone else alike."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    ticket_id TEXT NOT NULL, owner_id TEXT NOT NULL, note TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT NOT NULL, owner_id TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY (key, owner_id)
);
"""


def open_database(path=":memory:"):
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def seed_demo(db):
    with db:
        db.executemany(
            "INSERT OR REPLACE INTO tickets (id, owner_id, title, status) VALUES (?, ?, ?, ?)",
            [
                ("T-1", "alice", "Printer on floor 2 is offline", "open"),
                ("T-2", "alice", "Cannot reset password", "open"),
                ("T-3", "bob", "Laptop battery swelling", "open"),
            ],
        )


def find_tickets(db, user_id, text):
    rows = db.execute(
        "SELECT id, title, status FROM tickets WHERE owner_id = ? AND title LIKE ? ORDER BY id",
        (user_id, "%" + text + "%"),
    ).fetchall()
    return [{"id": r[0], "title": r[1], "status": r[2]} for r in rows]


def fetch_ticket(db, user_id, ticket_id):
    row = db.execute(
        "SELECT id, title, status FROM tickets WHERE id = ? AND owner_id = ?",
        (ticket_id, user_id),
    ).fetchone()
    if row is None:
        raise NotFound("ticket not found")
    return {"id": row[0], "title": row[1], "status": row[2]}


def _replay(db, user_id, idempotency_key):
    row = db.execute(
        "SELECT result FROM idempotency WHERE key = ? AND owner_id = ?",
        (idempotency_key, user_id),
    ).fetchone()
    return None if row is None else json.loads(row[0])


def insert_note(db, user_id, ticket_id, note, idempotency_key):
    fetch_ticket(db, user_id, ticket_id)
    previous = _replay(db, user_id, idempotency_key)
    if previous is not None:
        return previous
    result = {"ticket_id": ticket_id, "noted": True}
    with db:  # one transaction: both rows are written, or neither
        db.execute(
            "INSERT INTO notes (ticket_id, owner_id, note) VALUES (?, ?, ?)",
            (ticket_id, user_id, note),
        )
        db.execute(
            "INSERT INTO idempotency (key, owner_id, result) VALUES (?, ?, ?)",
            (idempotency_key, user_id, json.dumps(result)),
        )
    return result


def set_ticket_status(db, user_id, ticket_id, status, idempotency_key):
    before = fetch_ticket(db, user_id, ticket_id)
    previous = _replay(db, user_id, idempotency_key)
    if previous is not None:
        return previous
    result = {"ticket_id": ticket_id, "status": status, "previous_status": before["status"]}
    with db:
        db.execute(
            "UPDATE tickets SET status = ? WHERE id = ? AND owner_id = ?",
            (status, ticket_id, user_id),
        )
        db.execute(
            "INSERT INTO idempotency (key, owner_id, result) VALUES (?, ?, ?)",
            (idempotency_key, user_id, json.dumps(result)),
        )
    return result


def count_notes(db, user_id, ticket_id):
    row = db.execute(
        "SELECT COUNT(*) FROM notes WHERE ticket_id = ? AND owner_id = ?",
        (ticket_id, user_id),
    ).fetchone()
    return row[0]
