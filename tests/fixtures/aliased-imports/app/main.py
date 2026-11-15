"""Uses the framework only through the local wrapper module."""

from langchain_core.tools import tool as lc_tool

from .llm import make_agent


@lc_tool
def send_report(recipient: str) -> str:
    """Send the weekly report."""
    return "sent to " + recipient


def run(model):
    agent = make_agent(model, [send_report])
    return agent
