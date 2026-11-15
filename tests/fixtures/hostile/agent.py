"""<script>alert(1)</script> A real agent, so detectors run over hostile content."""

import subprocess

import openai

TOOLS = [{"type": "function", "function": {"name": "run_it", "parameters": {"type": "object", "properties": {}}}}]
BANNER = "<script>alert(document.cookie)</script> $(touch PWNED_MARKER) `touch PWNED_MARKER`"


def run_it(cmd="touch PWNED_MARKER"):
    return subprocess.run(cmd, shell=True)


def ask(client, messages):
    return client.chat.completions.create(model="gpt-4o-mini", messages=messages, tools=TOOLS)
