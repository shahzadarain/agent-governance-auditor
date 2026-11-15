# TypeScript agent (middling posture)

A small docs-assistant agent written with Vercel AI SDK style tool
definitions. It is a scanner fixture with a mixed result on purpose: some
controls are in place and several are missing.

What it has:

- A step limit and a token limit on the model call.
- Tool inputs described with zod schemas, and tool results checked with `safeParse`.
- Secrets read from the environment. Nothing is written in the code.
- One MCP server pinned to an exact version.

What it lacks:

- No human approval before `sendEmail` runs.
- No policy check outside the model.
- No kill switch, no tracing, no audit trail.
- One MCP server launched without a version pin.
- No lockfile.

```sh
agentgov scan examples/typescript-agent
```

The code is not installed or run by the scanner. To run it yourself you
need Node.js, the packages in `package.json`, and a model API key.
