"""Tool handlers, the tool registry, and the tool allowlist.

Handlers take a trusted context first. The context carries the session, so
the caller identity never comes from model-supplied arguments.
"""

from dataclasses import dataclass

from . import data


@dataclass
class ToolContext:
    session: object
    db: object
    memory: object


def search_tickets(ctx, text):
    return data.find_tickets(ctx.db, ctx.session.user_id, text)


def get_ticket(ctx, ticket_id):
    return data.fetch_ticket(ctx.db, ctx.session.user_id, ticket_id)


def add_note(ctx, ticket_id, note, idempotency_key):
    return data.insert_note(ctx.db, ctx.session.user_id, ticket_id, note, idempotency_key)


def close_ticket(ctx, ticket_id, idempotency_key):
    return data.set_ticket_status(ctx.db, ctx.session.user_id, ticket_id, "closed", idempotency_key)


def reopen_ticket_compensation(ctx, ticket_id, idempotency_key):
    """Operator-only undo for close_ticket. It is not exposed to the model."""
    return data.set_ticket_status(ctx.db, ctx.session.user_id, ticket_id, "open", idempotency_key)


def remember_preference(ctx, key, value):
    return ctx.memory.remember(ctx.session, key, value)


TOOL_HANDLERS = {
    "search_tickets": search_tickets,
    "get_ticket": get_ticket,
    "add_note": add_note,
    "close_ticket": close_ticket,
    "remember_preference": remember_preference,
}

# The only tools the model may call. Anything else is rejected at dispatch.
ALLOWED_TOOLS = frozenset(TOOL_HANDLERS)


def _schema(name, description, properties, required):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


_TEXT = {"type": "string"}

TOOL_SCHEMAS = [
    _schema("search_tickets", "Search the tickets of the signed-in user by title.", {"text": _TEXT}, ["text"]),
    _schema("get_ticket", "Read one ticket of the signed-in user.", {"ticket_id": _TEXT}, ["ticket_id"]),
    _schema("add_note", "Add a note to a ticket.",
            {"ticket_id": _TEXT, "note": _TEXT, "idempotency_key": _TEXT}, ["ticket_id", "note", "idempotency_key"]),
    _schema("close_ticket", "Close a ticket. Needs human approval.",
            {"ticket_id": _TEXT, "idempotency_key": _TEXT}, ["ticket_id", "idempotency_key"]),
    _schema("remember_preference", "Remember a preference for the signed-in user.",
            {"key": _TEXT, "value": _TEXT}, ["key", "value"]),
]

SCHEMA_BY_NAME = {entry["function"]["name"]: entry["function"] for entry in TOOL_SCHEMAS}
