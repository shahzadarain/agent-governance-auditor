"""Module alias: import langgraph.graph as lg."""

import langgraph.graph as lg


class State(dict):
    pass


def build():
    builder = lg.StateGraph(State)
    builder.add_node("start", lambda state: state)
    builder.set_entry_point("start")
    return builder.compile()
