# Framework support

This page says what the scanner recognizes for each framework and language, how it decides that an agent is present, and where the gaps are. It is written from the detection code in `internal/adapters`.

"Detected" on this page means the scanner recognizes the framework's imports and the way agents and tools are created with it. It does not mean every feature of the framework is understood.

## Contents

- [Languages](#languages)
- [Frameworks](#frameworks)
- [Detected or suspected](#detected-or-suspected)
- [How tools are found](#how-tools-are-found)
- [MCP configuration files](#mcp-configuration-files)
- [How versions are read](#how-versions-are-read)
- [Capabilities](#capabilities)
- [Monorepos](#monorepos)
- [Known gaps](#known-gaps)

## Languages

| Language | File types | Depth of analysis |
| --- | --- | --- |
| Python | `.py`, `.pyi` | Deepest. Imports and aliases, functions, decorators, keyword arguments, tool registries, and calls followed into local functions. |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` | Shallower. Imports, `require`, functions, and the first object argument of a call. See [Known gaps](#known-gaps). |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | Same as TypeScript. Files ending in `.min.js` and `.d.ts` are skipped. |
| Other languages | none | Not scanned. An agent written in Go, Java, C#, or Rust is not found. |

The scanner also reads YAML, JSON, and TOML files, Dockerfiles, dependency manifests, and lockfiles, because many controls live in configuration.

Analysis is lexical. The scanner removes comments and the contents of strings and then looks for patterns in what remains. It resolves import aliases, so `from langchain_core.tools import tool as lc_tool` is still recognized. It is not a compiler and it does not build a syntax tree.

## Frameworks

When several frameworks match one agent, the first match in this order is reported.

| Framework (ID in reports) | Python | TypeScript / JavaScript | Recognized by |
| --- | --- | --- | --- |
| LangGraph (`langgraph`) | Detected | Detected | Imports of `langgraph` or `@langchain/langgraph`, with `StateGraph`, `MessageGraph`, `create_react_agent`, `createReactAgent`, `create_supervisor`, `create_swarm`, or `ToolNode`. |
| LangChain (`langchain`) | Detected | Detected | Imports of `langchain`, `langchain_core`, the `langchain_*` provider packages, or `@langchain/*`, with `AgentExecutor`, the `create_*_agent` helpers, `initialize_agent`, `StructuredTool`, `DynamicStructuredTool`, `Tool`, or a call to `bind_tools` / `bindTools`. |
| OpenAI Agents SDK (`openai-agents`) | Detected | Detected | Imports of `agents` (Python) or `@openai/agents`, with `Agent`, `Runner`, or `run`. A local Python package named `agents` is ignored unless `openai-agents` is in a manifest. |
| CrewAI (`crewai`) | Detected | Not covered | Import of `crewai` with `Agent`, `Crew`, or `Task`. |
| AutoGen (`autogen`) | Detected | Not covered | Imports of `autogen`, `autogen_agentchat`, `autogen_core`, or `autogen_ext`, with `AssistantAgent`, `UserProxyAgent`, `ConversableAgent`, `GroupChat`, and related classes. |
| PydanticAI (`pydantic-ai`) | Detected | Not covered | Import of `pydantic_ai` with `Agent`. |
| MCP (`mcp`) | Detected | Detected | Imports of `mcp`, `fastmcp`, or `@modelcontextprotocol/sdk`, with `FastMCP`, `Server`, `McpServer`, `Client`, `ClientSession`, or the transport classes. A local Python module named `mcp` is ignored unless the package is in a manifest. |
| Direct tool calling (`generic-tool-calling`) | Detected | Detected | A model SDK is imported and a call passes `tools=` or `functions=`. See below. |

### Direct tool calling

Many agents use no agent framework. They call a model SDK and pass a list of tools. The scanner reports these as `generic-tool-calling`.

Model SDKs recognized by import:

- Python: `openai`, `anthropic`, `google.generativeai`, `google.genai`, `mistralai`, `cohere`, `groq`, `litellm`, `ollama`.
- TypeScript and JavaScript: `openai`, `@anthropic-ai/sdk`, `ai` and `@ai-sdk/*` (Vercel AI SDK), `@google/generative-ai`, `@google/genai`, `@mistralai/mistralai`, `ollama`.

An import alone is not enough. The code must also pass a `tools` or `functions` argument to a model call, or, in TypeScript and JavaScript, define a tool with the SDK's `tool(...)` helper. A program that only asks a model for text is not an agent and is not reported as one. In that case the result carries a note that a model client was found without tools.

The Vercel AI SDK has no adapter of its own. It is covered through this path.

## Detected or suspected

Each agent in a report has a detection state and a confidence.

| State | Confidence | When |
| --- | --- | --- |
| detected | high | The framework is imported and it is used: an agent or tool is constructed, a tool decorator is applied, or tools are passed to a model call. |
| suspected | medium | A framework is imported, but no usage was found. |
| suspected | low | A framework appears only in a dependency manifest, such as `requirements.txt` or `package.json`. |
| not detected | | Nothing above matched. No agent is reported. |

Two consequences:

- For a suspected agent, the scanner is careful. Several detectors report "missing" only for a detected agent. For a suspected agent those controls stay "unknown", and the inferred risk tier is "unknown".
- A framework name in a comment, a docstring, a string, or a Markdown file never counts. The test fixture `tests/fixtures/comments-only` exists to keep that true.

A declaration in `.agentgov.yaml` adds the ID, owner, and risk tier to an agent that was found in code. It does not create an agent. If the scanner finds no agent in the code, the result is "No AI agent was detected" even when the file declares one.

## How tools are found

A tool is a function the model can ask the agent to run. The scanner collects tools from:

- Functions with a tool decorator: `@tool`, `@function_tool`, `@tool_plain`, `@register_for_llm`, `@register_for_execution`.
- Names inside a `tools=` or `functions=` argument that resolve to functions in the project.
- Python registries: a dictionary whose name contains `tool`, `registry`, `handler`, `function`, `action`, `dispatch`, or `command`, with tool names as keys and functions as values.
- Tool schemas: an object with a `name` and a `parameters`, `input_schema`, or `inputSchema` close by.
- In TypeScript and JavaScript files that import a framework: `tool(...)`, `registerTool(...)`, `new DynamicStructuredTool(...)`, `new DynamicTool(...)`, and `new FunctionTool(...)`.

Test files are skipped.

A tool is marked **sensitive** when one of these is true:

- A word in its name is a sensitive verb, such as `delete`, `remove`, `transfer`, `pay`, `refund`, `send`, `execute`, `write`, `update`, `deploy`, `grant`, `revoke`, `close`, or `cancel`. Names are split into words first, so `payload` does not match `pay`.
- Its code, or a local function it calls within two steps, runs a shell command, evaluates code, sends an HTTP request that changes data, or writes to a database.
- `.agentgov.yaml` lists it under `capabilities.sensitive_actions`.

## MCP configuration files

Files named `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, or `mcp_config.json` are read wherever they are. For each server entry the scanner records the name, the transport (`stdio`, `http`, or `sse`), and whether the launch is pinned to a version.

A server started through `npx`, `uvx`, `pipx`, `docker`, or a similar launcher counts as pinned only with an exact version, a tag other than `latest`, or a digest. An unpinned server is reported under AGC-014.

Arguments and environment values of an MCP entry are never stored, because they often hold secrets. MCP servers are listed as connections of the agent. They are not counted as tools.

## How versions are read

The framework version in a report comes from the agent's own project folder:

- `requirements*.txt`, `pyproject.toml` (PEP 621, dependency groups, and Poetry), and `package.json` are read for dependencies.
- If the dependency is pinned to an exact version, that version is shown.
- Otherwise the scanner looks in `poetry.lock`, `uv.lock`, or `package-lock.json` next to the manifest.
- Otherwise the version is "unknown".

`pnpm-lock.yaml`, `yarn.lock`, `Pipfile.lock`, `pdm.lock`, and `bun.lock` are recognized as lockfiles for the supply chain check, but versions are not read from them. `Pipfile` and `setup.py` mark a project folder but are not read for dependencies.

## Capabilities

Capabilities describe what an agent can do. They decide which controls apply. The full list:

`tools`, `sensitive-actions`, `mutating-actions`, `shell-exec`, `code-exec`, `filesystem`, `network`, `browser`, `data-access`, `memory`, `multi-agent`, `mcp`, `credentials`, `container`.

Some examples of what triggers them:

| Capability | Triggered by |
| --- | --- |
| `shell-exec` | `subprocess`, `os.system`, `child_process`, and similar. |
| `data-access` | A database or vector store library, or `.execute(...)` calls. |
| `credentials` | Reading an environment variable whose name contains `key`, `token`, `secret`, or `password`, or a hardcoded credential assignment. |
| `multi-agent` | Handoffs, crews, group chats, supervisors, or an A2A import. |
| `container` | A Dockerfile, a Compose file, or a Kubernetes workload manifest in scope. |

The inferred risk tier follows from the capabilities. `shell-exec` or `code-exec` gives high. So does `sensitive-actions` together with `credentials` or `data-access`. Any other acting capability gives medium. The rest is low.

## Monorepos

Each folder that holds a `pyproject.toml`, `package.json`, `setup.py`, `Pipfile`, or `requirements*` file is a project root. Each root with agent evidence becomes its own agent with its own controls and its own decision. The repository decision is the most restrictive one. Shared files above the agents, such as CI workflows and Dockerfiles, count for every agent below them.

To declare several agents, use the `agents` list in `.agentgov.yaml` with a `root` for each. See [policy-reference.md](policy-reference.md).

## Known gaps

- **No LlamaIndex, Semantic Kernel, Google ADK, smolagents, Haystack, DSPy, Mastra, or cloud-hosted agent services.** Agents built with these are found only if they also pass tools to a recognized model SDK.
- **CrewAI, AutoGen, and PydanticAI are Python only.**
- **TypeScript and JavaScript are shallower than Python.** Local imports are followed only for relative paths (`./module`). Tools defined with `tool(...)` or `new DynamicStructuredTool(...)` are recorded by name, but the scanner does not look inside their code. Checks that need the body of a tool, such as SQL built from arguments or an unrestricted shell tool, say nothing for those tools. Tool registries in dictionaries are recognized only in Python.
- **One framework per agent.** If a project mixes two, only the first match is named.
- **Dynamic code is invisible.** Tools registered at run time, generated code, plugins loaded by name, and imports built from strings are not seen.
- **Python one-line multiple statements.** In `import a; import b` on one line, only the first statement is read.
- **Name-based judgments.** Whether a tool is sensitive depends partly on its name. A tool named `process` that deletes records through a library the scanner does not know is not marked sensitive. List such tools under `sensitive_actions` in `.agentgov.yaml`.

If the scanner missed your agent or named the wrong framework, please open an issue with the "False positive or wrong result" template and a small example. Missed cases become test fixtures. To add a framework, see [architecture.md](architecture.md#how-to-add-a-framework).
