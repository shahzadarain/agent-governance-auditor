"""A valid agent that sits next to broken files."""

import openai

TOOLS = [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object", "properties": {}}}}]


def get_weather():
    return "sunny"


def ask(client, messages):
    return client.chat.completions.create(model="gpt-4o-mini", messages=messages, tools=TOOLS)
