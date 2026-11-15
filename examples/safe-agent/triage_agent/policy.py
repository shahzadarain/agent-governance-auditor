"""Deterministic policy for tool calls. It lives outside the model.

The model cannot change these rules. A tool with no rule is denied, and any
error while evaluating a rule is a denial.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    requires_approval: bool = False


@dataclass(frozen=True)
class Rule:
    roles: frozenset
    approval: bool = False
    max_text: int = 2000


RULES = {
    "search_tickets": Rule(roles=frozenset({"support", "viewer"})),
    "get_ticket": Rule(roles=frozenset({"support", "viewer"})),
    "add_note": Rule(roles=frozenset({"support"})),
    "remember_preference": Rule(roles=frozenset({"support", "viewer"}), max_text=500),
    "close_ticket": Rule(roles=frozenset({"support"}), approval=True),
}


def evaluate(session, tool, arguments):
    rule = RULES.get(tool)
    if rule is None:
        return Decision(False, "no policy rule for this tool: default deny")
    if not (session.roles & rule.roles):
        return Decision(False, "caller role is not permitted to use this tool")
    for value in arguments.values():
        if isinstance(value, str) and len(value) > rule.max_text:
            return Decision(False, "argument is longer than the policy allows")
    return Decision(True, "allowed by rule", requires_approval=rule.approval)


def decide(session, tool, arguments, evaluator=evaluate):
    """Return the policy decision. Any failure of the evaluator is a denial."""
    try:
        decision = evaluator(session, tool, arguments)
    except Exception:
        return Decision(False, "policy engine error: default deny")
    if not isinstance(decision, Decision):
        return Decision(False, "policy engine returned no decision: default deny")
    return decision
