"""Billing agent built with the OpenAI Agents SDK."""

from agents import Agent, Runner, function_tool

CREDITS = {}


@function_tool
def lookup_balance(account: str) -> str:
    """Return the balance of an account."""
    return str(CREDITS.get(account, 0))


@function_tool
def issue_refund(account: str, amount: float) -> str:
    """Issue a refund to an account."""
    CREDITS[account] = CREDITS.get(account, 0) + amount
    return "refunded"


triage = Agent(name="triage", instructions="Route billing questions.")
billing = Agent(name="billing", instructions="Help with billing.", tools=[lookup_balance, issue_refund], handoffs=[triage])


def main(question):
    return Runner.run_sync(billing, question, max_turns=6)
