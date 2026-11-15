"""Order-support agent built with LangGraph create_react_agent."""

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

ORDERS = {
    "A-100": {"status": "shipped", "item": "keyboard"},
    "A-101": {"status": "processing", "item": "monitor"},
}


@tool
def lookup_order(order_id: str) -> str:
    """Return the status of an order."""
    order = ORDERS.get(order_id)
    return "unknown order" if order is None else f"{order['item']}: {order['status']}"


@tool
def cancel_order(order_id: str) -> str:
    """Cancel an order that has not shipped yet."""
    order = ORDERS.get(order_id)
    if order is None or order["status"] == "shipped":
        return "cannot cancel"
    order["status"] = "cancelled"
    return "cancelled"


model = ChatOpenAI(model="gpt-4o-mini", timeout=30, max_tokens=512)

# interrupt_before pauses the graph before the tools node, so a person can
# inspect the pending tool call and resume or stop the run.
agent = create_react_agent(
    model,
    tools=[lookup_order, cancel_order],
    checkpointer=MemorySaver(),
    interrupt_before=["tools"],
)


def ask(question: str, thread_id: str = "demo"):
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 8}
    return agent.invoke({"messages": [("user", question)]}, config=config)


if __name__ == "__main__":
    state = ask("Cancel order A-101.")
    print(state["messages"][-1])
