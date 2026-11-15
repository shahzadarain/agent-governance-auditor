"""Deliberately unsafe finance-processing agent.

This file is a demo fixture for AgentGov Auditor. Every problem in it is
intentional. Nothing here is a real credential, and the default run talks to
a built-in mock model, not to a network service.
"""

import json
import logging
import os
import sqlite3
import subprocess

try:
    import openai
except ImportError:  # the mock model below is used when the SDK is absent
    openai = None

logging.basicConfig(level=logging.INFO)

# Made-up values that only look like secrets. They are here to be detected.
OPENAI_API_KEY = "sk-EXAMPLEnotARealKeyEXAMPLEnotARealKey0000"
LEDGER_USER = "finance.admin@example.com"
LEDGER_PASSWORD = "Ledger-Demo-Passw0rd-NOT-REAL"

# A stop flag that nothing outside the process can change.
KILL = False

SYSTEM_PROMPT = (
    "You are a finance operations agent. You must never refund more than 100 "
    "without approval, and you must follow company policy at all times."
)

DB = sqlite3.connect(":memory:")
DB.execute("CREATE TABLE invoices (id TEXT, customer_id TEXT, user_id TEXT, amount REAL, refunded REAL)")
DB.execute("INSERT INTO invoices VALUES ('inv-1', 'cust-1', 'alice', 250.0, 0)")
DB.execute("INSERT INTO invoices VALUES ('inv-2', 'cust-2', 'bob', 990.0, 0)")


def lookup_invoice(customer_id, user_id):
    # SQL text is built from the tool arguments, and user_id comes from the model.
    query = f"SELECT id, amount FROM invoices WHERE customer_id = '{customer_id}' AND user_id = '{user_id}'"
    return DB.execute(query).fetchall()


def refund_payment(invoice_id, amount, auto_approve=True):
    # No human decision: the approval defaults to yes.
    if not auto_approve:
        return "refund needs approval"
    DB.execute("UPDATE invoices SET refunded = ? WHERE id = ?", (amount, invoice_id))
    DB.commit()
    return f"refunded {amount} on {invoice_id}"


def run_shell(command):
    # Runs whatever the model asks for.
    done = subprocess.run(command, shell=True, capture_output=True, text=True)
    return done.stdout


TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_invoice",
            "description": "Look up invoices for a customer.",
            "parameters": {
                "type": "object",
                "properties": {"customer_id": {"type": "string"}, "user_id": {"type": "string"}},
                "required": ["customer_id", "user_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "refund_payment",
            "description": "Refund an invoice.",
            "parameters": {
                "type": "object",
                "properties": {"invoice_id": {"type": "string"}, "amount": {"type": "number"}},
                "required": ["invoice_id", "amount"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Run a shell command on the host.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
]


class MockModel:
    """A scripted stand-in for a chat model. It makes no network calls."""

    def __init__(self):
        self.script = [
            {"tool": "lookup_invoice", "arguments": {"customer_id": "cust-1", "user_id": "alice"}},
            {"tool": "refund_payment", "arguments": {"invoice_id": "inv-1", "amount": 250.0}},
            {"final": "Refund issued."},
        ]

    def create(self, messages, tools):
        return self.script.pop(0) if self.script else {"final": "Done."}


MOCK = MockModel()


def call_model(messages):
    if openai is not None and os.environ.get("VULNERABLE_AGENT_USE_REAL_MODEL"):
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        reply = client.chat.completions.create(model="gpt-4o-mini", messages=messages, tools=TOOL_SCHEMAS)
        message = reply.choices[0].message
        if message.tool_calls:
            call = message.tool_calls[0]
            return {"tool": call.function.name, "arguments": json.loads(call.function.arguments)}
        return {"final": message.content}
    return MOCK.create(messages=messages, tools=TOOL_SCHEMAS)


def dispatch(name, arguments):
    # Any function in this module can be called by name.
    handler = globals()[name]
    return handler(**arguments)


def run_agent(task):
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": task}]
    while True:
        if KILL:
            break
        logging.info(f"sending prompt to model: {messages}")
        print(f"using key {OPENAI_API_KEY}")
        reply = call_model(messages)
        if "final" in reply:
            return reply["final"]
        result = dispatch(reply["tool"], reply["arguments"])
        messages.append({"role": "tool", "content": str(result)})
    return "stopped"


if __name__ == "__main__":
    print(run_agent("Refund invoice inv-1 for customer cust-1."))
