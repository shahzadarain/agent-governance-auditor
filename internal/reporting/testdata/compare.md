## AgentGov Auditor scan comparison

Commits: 4f9c2d7 to 9e8d7c6

| Measure | Before | After |
|---|---|---|
| Release decision | BLOCK | BLOCK |
| Assessment maturity (illustrative only) | 21/100 | 25/100 |

**Findings:** 1 new, 1 resolved, 7 unchanged

### New findings

| Severity | Control | Finding | Location |
|---|---|---|---|
| Medium | AGC-012 | Agent loop has no step limit | src/agent/graph.py:57 |

### Resolved findings

| Severity | Control | Finding | Location |
|---|---|---|---|
| Critical | AGC-008 | Credential written in source code | src/agent/config.py:9 |

### Control changes

| Control | Agent | Before | After |
|---|---|---|---|
| AGC-008 | finance-processing-agent | Failed (0/4) | Implemented (not yet tested) (2/4) |
| AGC-012 | finance-processing-agent | Verified in operation (4/4) | Verified by tests (3/4) |

---

This is an evidence-based assessment, not a certification.
