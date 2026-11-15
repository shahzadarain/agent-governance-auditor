# Test fixtures

Small directories used by the Go tests of the detection engine. Each one
targets one behavior. They are never executed.

| Fixture | Purpose |
| --- | --- |
| `no-agent/` | An ordinary web app. Discovery must report zero agents. |
| `comments-only/` | Framework names only in comments, docstrings, strings, and Markdown. Zero agents. |
| `aliased-imports/` | Aliased and wrapped framework imports must still resolve. |
| `malformed/` | Broken YAML, JSON, TOML, and Python. Warnings, no crash, no pass. |
| `monorepo/` | Two agents in one repository. |
| `unicode-paths/` | Non-ASCII directory and file names. |
| `hostile/` | Files that would create a marker file if anything executed them. |
