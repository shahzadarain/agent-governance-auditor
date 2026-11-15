# Use cases

*Written by Shahzad Asghar.*

I started this project because of a pattern I kept seeing. Building an agent
has become easy. A weekend is enough to wire a model to a few tools and have it
send emails, update records, or run commands. Checking that the agent is safe
to release has not become easy at all. That part is still a long document, a
meeting, and a lot of guessing.

I wanted something closer to a spell checker. You point it at a folder, it
tells you what is in place and what is not, and it shows you where to look.
You should not need a security background to read the result.

Below are the situations I had in mind. None of them are customer stories.
The tool is new and I am not going to invent any. They are the cases I
designed for, and each one ends with commands you can run today.

---

## 1. "I built an agent. Is it okay to ship?"

**Who:** a developer, or someone who put an agent together with a framework and
some tutorials.

You have a working agent. It calls tools. Someone asks whether it is safe, and
you honestly do not know how to answer.

```sh
agentgov scan . --open
```

You get a page in your browser. At the top is one of three words: ALLOW,
BLOCK, or REVIEW REQUIRED. Under it is a short list called "What to fix
first". Every item has a sentence in plain words, the file and line, and the
steps to fix it.

If a term is unclear:

```sh
agentgov explain AGC-010
```

That prints what the control means, why it exists, and what counts as proof.

**What you walk away with:** a short, ordered to-do list instead of a vague
worry.

---

## 2. "I am starting from zero and want to do it properly"

**Who:** anyone starting a new agent, including people who do not write much
code.

Most agents get their safety pieces added late, if at all. It is far easier
to start with them and swap in your own tools afterwards.

```sh
agentgov new my-agent
cd my-agent
python tools/run_governance_tests.py
agentgov scan .
```

The first command creates a small working agent in plain Python. It needs no
extra packages. It already has the parts people tend to skip: a list of
allowed tools, a policy check, an approval step for risky actions, an
emergency stop, step limits, a trace of every step, and a log that shows if
someone edits it. The second command runs the tests that prove those parts
work and saves the result as evidence. The scan then reads that evidence.

**What you walk away with:** a starting point where the controls are real
code with real tests, and a scan result that reflects that.

---

## 3. "Stop risky changes before they merge"

**Who:** a team lead or DevOps engineer.

One pull request removes the approval step from a refund tool. Nobody
notices, because the diff is long and the reviewer is busy.

Add one step to your GitHub workflow:

```yaml
- uses: shahzadarain/agent-governance-auditor@main
  with:
    path: .
    fail_on: block
```

Every pull request now gets a summary. If a required control fails, the check
fails and the summary names the control and the file.

Pull requests can also edit the configuration file, so there is a guard for
that. Keep your organization's minimum requirements in a file outside the
repository and pass it with `baseline`. A pull request can add requirements.
It cannot lower yours.

**What you walk away with:** a gate that catches the removal of a safety
control the same way tests catch a broken function.

---

## 4. "I have to sign off on this agent and I do not read code"

**Who:** a risk owner, product manager, or compliance reviewer.

You are asked to approve an agent for production. You get a slide that says
"guardrails implemented". You have no way to check that.

Ask the team for one file:

```sh
agentgov scan . --format html --output report.html
```

Open it in any browser. It works offline and can be attached to an email or
a ticket. The 24 controls are grouped into six areas. Each one shows a
status in words, not only a color:

| Status | What it means |
|--------|---------------|
| Verified in operation | There is proof from the running system. |
| Verified by tests | Tests that try to break the control have passed for this exact version. |
| Implemented (not yet tested) | The code is there. Nobody has proven it works. |
| Declared only | Someone wrote that it exists. That is all. |
| Missing | The tool looked for it and did not find it. |
| Failed | The tool found something that breaks the control. |
| Unknown (needs evidence) | This cannot be judged from the code. Ask for proof. |

The difference between "implemented" and "verified by tests" is the question
to ask in the review meeting.

**What you walk away with:** a document you can read, question, and file.

---

## 5. "We have many agents and I have lost track"

**Who:** a platform or security team.

Three teams, nine agents, and a spreadsheet nobody has updated since March.

Run the dashboard on your own machine or server:

```sh
agentgov serve
```

Then have each repository send its scan result after every build:

```sh
agentgov scan . --upload-url http://127.0.0.1:8080
```

The dashboard lists every agent with its owner, its tools, its latest
decision, and how its results changed over time. Only the scan result is
sent. Source code stays where it is.

**What you walk away with:** one place that shows which agents exist and
which ones are blocked, kept current by the builds themselves.

---

## 6. "Prove it, do not just claim it"

**Who:** teams whose agents handle money, private data, or anything hard to
undo.

For these agents "the code looks right" is not enough. The tool keeps four
levels apart on purpose:

1. Declared: you say it exists.
2. Implemented: the code is there.
3. Tested: tests that attack the control have passed for this exact version.
4. In operation: there is proof from the running system.

Reading code can take you to level 2 and no further. Levels 3 and 4 need
evidence files produced by your tests or your runtime. Each file is tied to
the exact content it was produced from. Change the code and the old evidence
stops counting until you run the tests again.

You can also sign the evidence so a reviewer knows it came from your build
system and not from someone's laptop:

```sh
agentgov evidence keygen
agentgov evidence sign .agentgov/evidence/governance-tests.json --key agentgov-evidence.key
agentgov scan . --profile high-risk --trust-key agentgov-evidence.pub
```

**What you walk away with:** a result where "verified" means somebody
actually checked.

---

## 7. "Did we get better or worse?"

**Who:** anyone preparing a release.

```sh
agentgov scan . --format json --output before.json
# make your changes
agentgov scan . --format json --output after.json
agentgov compare before.json after.json
```

You see which findings are new, which are resolved, and which controls moved
up or down.

**What you walk away with:** a clear before and after for a release note or
a review.

---

## What this tool is not

I would rather be direct about the limits.

- It is not a certificate. A good result does not mean your agent is safe.
- It does not replace a security review or a penetration test.
- It audits. It does not sit inside your agent and block actions at runtime.
- It reads code with pattern-aware analysis, not a full compiler. It will
  miss things, and sometimes it will flag things that are fine. When it
  cannot tell, it says "unknown" instead of guessing.
- The score is a summary for humans. One failed required control blocks a
  release no matter how high the score is.

If one of these cases is close to yours but something does not fit, open an
issue and tell me what you were trying to do. That is the most useful
feedback I can get.
