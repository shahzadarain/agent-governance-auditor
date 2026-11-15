# Writing a detector

A detector is a small piece of Go code that looks at a repository and reports evidence for one governance control. This guide walks through adding one, with fixtures and tests.

Read [CONTRIBUTING.md](../CONTRIBUTING.md) first for setup and the check command.

> The code in this guide is a simplified sketch. The real interface, type names, and registration call live in `internal/rules` and `internal/model`. Open two or three existing detectors in `internal/rules` and copy their shape. If this guide and the code disagree, the code is right; please open an issue so we can fix the guide.

## Before you start

Ask three questions:

1. **Which control does this support?** Run `agentgov controls list` and `agentgov controls show <ID>`. A detector belongs to exactly one control. If no control fits, you are proposing a new control, which needs a design review (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
2. **What can source code actually show?** A file can show that a check exists in code. It cannot show that the check runs in production. Write down what your pattern proves and what it does not.
3. **What does a miss look like?** Think of code that looks similar but does not implement the control. That becomes your negative fixture.

For a new detector family, open a "New detector" issue first.

## Honesty rules

These rules are not optional. Reviewers check each one.

1. **Never claim more than "implemented".** Static analysis reaches maturity level 2 at most. A detector that reads source files must not emit evidence with a strength of "tested" or "operational". Those levels need test results or runtime evidence from outside the scan.
2. **Prefer no evidence over a wrong claim.** If the pattern is ambiguous, emit nothing, or emit evidence with low confidence and a stated limitation. A control that shows as unknown is honest. A control that shows as implemented by mistake is harmful.
3. **A declaration is not an implementation.** A YAML key, a comment, or a README sentence that says a control exists is "declared" evidence only.
4. **Missing evidence is not a vulnerability.** Emit a violation only when the code shows a concrete problem, such as a hardcoded credential or a shell call with unchecked model output. Do not emit a violation because you found nothing.
5. **Never print secret values.** Summaries, descriptions, fingerprints, and log lines must not contain a matched secret, token, or credential. Report the kind of secret and the location. Build fingerprints from the rule ID, path, and structure, never from the secret text.
6. **Never execute or import scanned code.** Detectors read bytes. They do not run scripts, resolve packages over the network, or follow links out of the scan root.
7. **State limitations.** Every piece of evidence carries a list of limitations. Say what the detector did not check.
8. **Stay deterministic.** The same input must give the same output, in the same order. Do not read the clock, the environment, or the network. Sort anything you collect from a map.

## Step 1: pick the control and a rule ID

Rule IDs have the form `<control ID>.<short-name>`, for example `AGC-008.hardcoded-secret`. Choose a short name that describes what the rule observes. Rule IDs are stable: once released, an ID keeps its meaning. Check the existing IDs so yours does not collide.

## Step 2: create the detector file

Create `internal/rules/<name>.go`. Use a lowercase file name that matches the rule, for example `mcp_pinning.go`.

A detector does three things:

- It declares its ID and the control it supports.
- It receives the parsed view of the repository (files, agents, tools, facts from the adapters).
- It returns evidence, and sometimes findings.

Simplified sketch:

```go
package rules

// exampleDetector reports whether tool calls pass through an approval check.
// Check existing detectors for the exact interface and type names.
type exampleDetector struct{}

func (exampleDetector) ID() string        { return "AGC-0XX.example-check" }
func (exampleDetector) ControlID() string { return "AGC-0XX" }

func (exampleDetector) Detect(in Input) Output {
	var out Output
	for _, f := range in.Files {
		// Work on the adapter's view of the file. The adapters already
		// remove comments and string literals, so a keyword inside a
		// comment does not count as an implementation.
		loc, ok := findApprovalCheck(f)
		if !ok {
			continue
		}
		out.Evidence = append(out.Evidence, Evidence{
			Signal:      "present",
			Strength:    "implementation", // never higher from static analysis
			Location:    loc,
			Summary:     "Approval check found before a sensitive tool call.",
			Limitations: []string{"Does not prove the check runs on every path."},
		})
	}
	return out
}
```

Guidelines for the detection logic:

- Use the adapter output in `internal/adapters`. Do not run a regular expression over raw file text when an adapter view exists. Raw text matches comments and strings, which causes false positives.
- Resolve import aliases through the adapter. `import subprocess as sp` followed by `sp.run(...)` is still a subprocess call.
- Bind evidence to a file and line whenever you can.
- Keep each detector small. Two narrow detectors are better than one that tries to cover everything.
- Handle bad input without a panic. Files can be truncated, binary, very large, or in an unexpected encoding.

## Step 3: register the detector

Detectors are registered in `internal/rules` so the engine can run them. Each domain file has an `init` function that calls `register(controlID, shortName, runFunction)`, for example `register("AGC-001", "owner-inventory", runOwnerInventory)` in `accountability.go`. Add your call there. The existing detectors live in one file per domain (`accountability.go`, `identity.go`, `actions.go`, `assurance.go`) and their table-driven tests are in `rules_test.go`. The test `TestRegistryCoversAllControlsInOrder` checks the registry.

## Step 4: add fixtures

Fixtures are small sample inputs under `tests/fixtures/`. Follow the folder layout that existing fixtures use. Add at least three:

| Fixture | Purpose | Expected result |
| --- | --- | --- |
| Positive | Code that implements the control | Evidence with signal "present", strength "implementation" |
| Negative | Similar-looking code that does not implement it | No "present" evidence |
| Malformed | Broken syntax, truncated file, or odd encoding | No panic, no false claim |

Add more negatives when you can. Good ones include:

- The keyword appears only in a comment or a string.
- The helper function exists but nothing calls it.
- The name matches but the import comes from a different library.

Fixture rules:

- Keep fixtures minimal. Ten lines are better than a hundred.
- Fixtures are never executed. Make any risky-looking string inert.
- Never include a real key, token, password, or private data. Use obvious fakes such as `sk-EXAMPLE-not-a-real-key`.
- Do not copy code from projects with an incompatible license.

## Step 5: write table-driven tests

Add `internal/rules/<name>_test.go`. Use one table with a row per fixture.

Simplified sketch:

```go
func TestExampleDetector(t *testing.T) {
	cases := []struct {
		name        string
		fixture     string
		wantPresent bool
	}{
		{"approval check before tool call", "example/positive", true},
		{"keyword only in a comment", "example/negative_comment", false},
		{"helper defined but never called", "example/negative_unused", false},
		{"truncated file", "example/malformed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runDetector(t, exampleDetector{}, tc.fixture) // see existing tests for the helper
			if got := hasPresentEvidence(out); got != tc.wantPresent {
				t.Fatalf("present evidence = %v, want %v", got, tc.wantPresent)
			}
			for _, ev := range out.Evidence {
				if ev.Strength != "implementation" && ev.Strength != "declaration" {
					t.Fatalf("static detector emitted strength %q", ev.Strength)
				}
			}
		})
	}
}
```

Also test, where it applies:

- The reported line number is correct.
- The summary and the fingerprint do not contain the matched secret value.
- Two runs over the same fixture give identical output.

## Step 6: check the result end to end

```sh
go test ./internal/rules/...
go build -o agentgov ./cmd/agentgov
./agentgov scan examples/safe-agent --full
./agentgov scan examples/vulnerable-agent --full
```

Then run the full check (`make check`, `bash scripts/check-all.sh`, or `powershell -File scripts/check.ps1`).

Look at the real output. Ask whether a developer who is not a security specialist would understand what was found, why it matters, and what to do next.

## Step 7: document it

- Add or update the rule entry in the rule documentation, if that page exists yet.
- If the detector changes what the tool can verify, update `docs/IMPLEMENTATION_STATUS.md`.
- Describe known false-positive and false-negative cases in the pull request.

## Review checklist

A reviewer will check that:

- [ ] The detector maps to exactly one existing control.
- [ ] The rule ID is new, stable, and descriptive.
- [ ] No evidence has a strength above "implementation".
- [ ] Positive, negative, and malformed fixtures exist.
- [ ] Tests are table-driven, offline, and deterministic.
- [ ] No secret value appears in any output or fixture.
- [ ] Limitations are stated in the evidence.
- [ ] The full check passes.

## Changing an existing detector

The same rules apply. In addition:

- Add a fixture that shows the case you are fixing. For a false positive, add it as a negative fixture.
- Do not change the meaning of an existing rule ID. If the meaning changes, create a new ID and note the old one as retired.
- State in the pull request whether results for existing users can change.
