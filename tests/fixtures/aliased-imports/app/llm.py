"""Local wrapper around the framework: one hop away from the caller."""

from langgraph.prebuilt import (
    create_react_agent as make_react,
)


def make_agent(model, tools):
    return make_react(model, tools=tools)
