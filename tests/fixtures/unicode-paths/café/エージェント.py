"""Agent in a directory and file with non-ASCII names. Größe: klein."""

import anthropic

TOOLS = [
    {
        "name": "übersetzen",
        "description": "Translate text.",
        "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
    {
        "name": "translate_text",
        "description": "Translate text.",
        "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
]


def translate_text(text):
    return text[::-1]  # placeholder transformation: "日本語" stays data


def ask(client: "anthropic.Anthropic", frage):
    return client.messages.create(model="claude-sonnet-4-5", max_tokens=256, messages=frage, tools=TOOLS)
