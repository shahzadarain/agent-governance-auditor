# LangGraph example

A small order-support agent built with LangGraph `create_react_agent`. It
shows two framework-native controls that the scanner recognizes:

- `interrupt_before=["tools"]` pauses the graph before any tool runs, so a
  person can review the pending call (AGC-010).
- `recursion_limit` bounds the number of graph steps (AGC-012).

Everything else is left out on purpose, so a scan shows a realistic mix of
present and missing controls.

```sh
agentgov scan examples/python-langgraph
```

To run it yourself, install the pinned packages in `requirements.txt` and
set a model API key. The scanner does neither.
