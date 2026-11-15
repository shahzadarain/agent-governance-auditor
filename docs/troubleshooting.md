# Troubleshooting

Find the problem you see in the list and go to its section. If yours is not here, run `agentgov doctor` and open an issue with its output.

## Contents

- ["agentgov is not recognized" or "command not found"](#agentgov-is-not-recognized-or-command-not-found)
- [PowerShell will not run the program from the current folder](#powershell-will-not-run-the-program-from-the-current-folder)
- [Paths with spaces](#paths-with-spaces)
- [The build fails](#the-build-fails)
- [There is no color](#there-is-no-color)
- [No agent was detected](#no-agent-was-detected)
- [Many controls are "Unknown"](#many-controls-are-unknown)
- [A result looks wrong](#a-result-looks-wrong)
- [A control cannot be met in my situation](#a-control-cannot-be-met-in-my-situation)
- [Evidence stopped counting after I edited a file](#evidence-stopped-counting-after-i-edited-a-file)
- [Signed evidence is reported as invalid](#signed-evidence-is-reported-as-invalid)
- [AGC-001 blocks under my baseline](#agc-001-blocks-under-my-baseline)
- [Exit code 2](#exit-code-2)
- [The JSON output is empty](#the-json-output-is-empty)
- [Upload is refused over plain HTTP](#upload-is-refused-over-plain-http)
- [Upload says the token variable is empty](#upload-says-the-token-variable-is-empty)
- [SARIF upload is refused on a private repository](#sarif-upload-is-refused-on-a-private-repository)
- [The commit shows as "unknown"](#the-commit-shows-as-unknown)

## "agentgov is not recognized" or "command not found"

The terminal cannot find the program.

**If you built with `go build`**, the program is a file in the folder where you built it. Run it with its path.

```powershell
.\agentgov.exe doctor
```

```sh
./agentgov doctor
```

**If you used `go install`**, the program is in your Go bin folder, and that folder must be on your `PATH`. Find the folder:

```sh
go env GOPATH
```

The program is in the `bin` folder under the path that this prints. On Windows that is usually `C:\Users\<you>\go\bin`. To add it for the current PowerShell window:

```powershell
$env:PATH += ";$(go env GOPATH)\bin"
```

On macOS or Linux, for the current terminal:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
```

Then close and reopen the terminal if you changed the setting permanently, and run `agentgov doctor`.

## PowerShell will not run the program from the current folder

PowerShell does not run a program from the current folder by its bare name. This is a PowerShell safety rule, not an error in the tool. Put `.\` in front:

```powershell
.\agentgov.exe scan examples\vulnerable-agent
```

`agentgov` is a normal program, not a PowerShell script, so the script execution policy does not apply to it. If Windows shows a warning about an unrecognized app for a file you downloaded, build the program from source as described in the [step-by-step guide](getting-started.md#step-1-install). There are no official downloads yet.

## Paths with spaces

Put quotes around a path that contains a space.

```powershell
agentgov scan "C:\Users\me\My Projects\support agent"
```

```sh
agentgov scan "/home/me/my projects/support agent"
```

## The build fails

- Run `go version`. The project needs Go 1.27 or newer.
- Run the build from the repository folder, the one that contains `go.mod`.
- The first build downloads Go modules. It needs internet access once. Scans do not.
- You do not need a C compiler. The project uses no cgo.

## There is no color

Color is used only when the output goes to a real terminal. It is off when:

- you redirect or pipe the output,
- the variable `NO_COLOR` is set,
- you pass `--no-color`,
- the terminal reports itself as `dumb`.

`agentgov doctor` tells you whether color is on. Nothing is lost without color: every status is also written as a word or a mark, such as `[ok]` and `[x]`.

To keep color when piping, for example into a pager:

```powershell
$env:CLICOLOR_FORCE = "1"
agentgov scan .
```

```sh
CLICOLOR_FORCE=1 agentgov scan . | less -R
```

## No agent was detected

The scan says "No AI agent was detected" and the decision is `REVIEW REQUIRED`. This is not a pass. Nothing was assessed.

Check these in order:

1. **The folder.** Did you scan the folder that holds the agent code? `agentgov scan .` scans the folder you are in.
2. **The language.** Only Python, TypeScript, and JavaScript are scanned.
3. **The framework.** The scanner knows the frameworks listed in [framework-support.md](framework-support.md). For code that calls a model SDK directly, it must see a `tools` or `functions` argument on the model call. A program that only asks a model for text is not treated as an agent.
4. **Skipped files.** Run with `-v` to see how many files were scanned and skipped. Files over 1 MiB and folders such as `node_modules`, `dist`, `build`, and `.venv` are skipped. If your code lives in a folder with one of those names, the scanner does not see it.
5. **Dynamic code.** Tools that are registered at run time or loaded by name are not seen.

The message suggests running `agentgov init`. Be aware of what that does and does not do. `init` writes a `.agentgov.yaml` that describes your agent, and you should have one. In this version a declaration alone does not make the scanner assess an agent that it cannot find in code. The result stays "No AI agent was detected".

If your agent uses a supported language and you think it should have been found, please open an issue with a small example. That is how detection improves.

## Many controls are "Unknown"

"Unknown" means the scanner could not judge the control from code, in either direction. It is not a failure and not a pass.

Common reasons:

- **The control is not visible in code.** Token lifetimes set in an identity provider (AGC-006), a workload identity defined in a cloud console (AGC-004), or secrets injected by a platform (AGC-008) leave little trace in a repository.
- **The agent is "suspected", not "detected".** When the scanner sees a framework import but no usage, it holds back and leaves several controls unknown.
- **TypeScript or JavaScript.** Analysis is shallower for these languages. See [framework-support.md](framework-support.md#known-gaps).
- **The control is there in a form the detector does not recognize.** [CONTROL_COVERAGE.md](CONTROL_COVERAGE.md) lists what each detector looks for.

What to do:

1. Run `agentgov explain <ID>` and read "How it is verified".
2. Supply evidence. A test that exercises the control, with an evidence file, raises it to level 3. See [evidence.md](evidence.md).
3. If a mandatory control is unknown, the decision is `BLOCK` until there is evidence or a recorded exception.

## A result looks wrong

The scanner reads code as text and matches patterns. It will sometimes flag code that is fine and sometimes credit code that is not.

First, check what it saw:

```sh
agentgov scan . --open
```

In the report, open the control. It shows the evidence, the file and line, and the reason for the status.

**If the scanner flagged something that is fine (a false positive):**

- Please report it with the "False positive or wrong result" issue template. Include the rule ID (for example `AGC-008.hardcoded-secret`), the smallest snippet that reproduces it with secrets removed, and what you expected. Reported cases become test fixtures.
- Do not hide it by editing the configuration unless a person has reviewed it. If a reviewer agrees that the risk is acceptable for now, record it. See the next section.

**If the scanner missed a control that exists:**

- Check [CONTROL_COVERAGE.md](CONTROL_COVERAGE.md) for the patterns the detector recognizes. A different function name can be enough.
- Supply test evidence. That is stronger than static detection anyway.
- Report it with the same issue template.

**If the scanner credited something that does not work:** report it. That is the most serious kind of wrong result.

## A control cannot be met in my situation

There are two recorded exceptions in `.agentgov.yaml`. Both need a reason and the name of the approver, and both are shown in every report.

```yaml
policy:
  not_applicable:
    - control: AGC-016
      reason: "Single agent. It does not exchange messages with other agents."
      approved_by: governance-review-board
      expires: "2027-06-30"
  accepted_risks:
    - control: AGC-021
      reason: "Red-team exercise is scheduled for the next quarter."
      approved_by: chief-information-security-officer
      expires: "2027-03-31"
```

| | `not_applicable` | `accepted_risks` |
| --- | --- | --- |
| Use it when | The control has no meaning for this agent. | The gap is real and someone accepted it for a time. |
| On a mandatory control | The control counts as met. | The decision becomes `REVIEW REQUIRED`. An accepted risk is not a pass. |
| Hides a violation | No | No |

Neither exception hides a finding. If the scanner found a hardcoded secret, an exception does not remove it. Details are in [policy-reference.md](policy-reference.md#exceptions).

## Evidence stopped counting after I edited a file

This is intended. Each evidence item is tied to the exact content of the files it covers. When one of those files changes, the item no longer matches.

You will see a control fall from "Verified by tests" to "Implemented (not yet tested)". To see why:

```sh
agentgov evidence verify .agentgov/evidence/governance-tests.json
```

A changed file shows as:

```text
AGC-017  pass     validity=digest-mismatch integrity=unsigned  (the subject files changed after the evidence was collected)
```

Fix: run your tests again so that they write fresh evidence. In the starter agent that is `python tools/run_governance_tests.py`. If you sign evidence, sign the new file.

The same happens when evidence passes its `valid_until` date. The reason is then `expired`.

## Signed evidence is reported as invalid

```text
validity=invalid-signature integrity=invalid  (the item is signed, but no trusted key was supplied to verify it)
```

Once an item carries a signature, it must verify. Pass the public key:

```sh
agentgov scan . --trust-key agentgov-evidence.pub
agentgov evidence verify .agentgov/evidence/governance-tests.json --trust-key agentgov-evidence.pub
```

If the message is "the signature does not verify against any trusted key", the file was changed after signing or was signed with a different key. Regenerate and sign again.

## AGC-001 blocks under my baseline

```text
Mandatory control AGC-001 (Owner and Inventory) is at maturity 1 (declared-only). The profile requires 2.
```

A scan can only see a declaration for AGC-001, so it stops at level 1. The built-in `baseline` and `standard` profiles make an exception for this one control and accept level 1.

A baseline file with `min_maturity: 2` or higher removes that exception. The baseline's general minimum is applied to every mandatory control, AGC-001 included, and a `control_min_maturity` entry in the baseline cannot lower it again. The result is a block on AGC-001 for every repository, including the safe example. I confirmed this with the example baseline in the policy reference.

Two ways out:

- If the baseline is there to add mandatory controls, set `min_maturity: 1` in it. The profile's own minimum of 2 still applies to every other mandatory control, because the stricter value wins, and the exception for AGC-001 stays.
- If you do want AGC-001 at level 2 or higher, supply external evidence for it, such as a signed attestation from the owner. The `high-risk` profile asks for that on purpose.

## Exit code 2

Exit code 2 means the scan could not run. It is not a policy result. The message after `agentgov: error:` says why. Common causes:

| Message contains | Cause |
| --- | --- |
| `scan path "..." does not exist` | A wrong folder. |
| `configuration is not valid` | A mistake in `.agentgov.yaml`. Run `agentgov policy validate .agentgov.yaml`. It names the field. |
| `organization baseline is not valid` | The file given with `--baseline`, or named in the `AGENTGOV_BASELINE` variable, is missing or wrong. |
| `--fail-on must be block, review, or never` | A misspelled flag value. |
| `upload failed (the scan itself completed)` | The scan worked and the upload did not. See the two upload sections below. |
| `scan timed out` | A very large folder. Raise `--timeout` or narrow the scan with `--include`. |

Exit code 1 is different: the scan ran and the release policy failed. In CI, treat 1 as "fix the agent" and 2 as "fix the pipeline".

## The JSON output is empty

`--quiet` suppresses everything on the screen, including a report in `--format json`. To capture JSON in a script, write it to a file:

```sh
agentgov scan . --json-out results.json --quiet
```

Or keep the report on standard output and turn off only the progress messages:

```sh
agentgov scan . --format json --no-progress
```

## Upload is refused over plain HTTP

```text
refusing to send the token over plain HTTP to a non-local host; use https or pass --upload-allow-http
```

The upload carries a token. Over plain HTTP, anyone on the network path could read it. The tool allows plain HTTP only to your own machine, such as `http://127.0.0.1:8080`.

Fix: put the server behind a reverse proxy with HTTPS and use an `https://` address. See [self-hosting.md](self-hosting.md#reverse-proxy-and-https). The flag `--upload-allow-http` exists for closed test networks. Do not use it over a network you do not control.

## Upload says the token variable is empty

```text
environment variable AGENTGOV_TOKEN is empty; set it to a project upload token
```

Create an upload token for the project in the dashboard, then set it for the current terminal:

```powershell
$env:AGENTGOV_TOKEN = "<project upload token>"
```

```sh
export AGENTGOV_TOKEN="<project upload token>"
```

In GitHub Actions, store the token as a secret and pass it with the action's `token` input.

## SARIF upload is refused on a private repository

GitHub code scanning is available for public repositories and for private repositories with GitHub Code Security. On a private repository without it, GitHub refuses the SARIF upload.

What happens in the action: the upload step fails, the job continues, and the release decision is not affected. You still get the job summary and the artifact, which contains the SARIF file.

What to do:

- Leave `upload_sarif` at its default of `false` on repositories without code scanning.
- Check that the job has the `security-events: write` permission where code scanning is available.
- Pull requests from forks cannot upload SARIF, because their token is read-only.

More in [github-action.md](github-action.md#code-scanning-sarif).

## The commit shows as "unknown"

The tool reads the commit from the `.git` folder without calling Git. It shows "unknown" when the folder is not a Git repository, or when `.git` is a file and not a folder, which is the case in a Git worktree and in a submodule. The scan itself is not affected. Evidence that is bound to a commit cannot be matched in that situation, so bind evidence to file content with a subject digest.
