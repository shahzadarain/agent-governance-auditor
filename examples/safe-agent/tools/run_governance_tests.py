"""Run the governance tests and write an external evidence file.

Usage (from the agent directory):

    python tools/run_governance_tests.py

For every control below, the script runs the tests that exercise the real
implementation. It then writes .agentgov/evidence/governance-tests.json in
the AgentGov external evidence format:

- All tests for a control passed: signal "present", result "pass".
- Any test failed, errored, or was skipped: signal "violation", result "fail".

Each item is bound to the exact content of the implementation and test files
through a subject digest, so the evidence stops counting as soon as one of
those files changes. The file is unsigned. Sign it with the AgentGov CLI if
your profile requires signed evidence.

Only the standard library is used. Nothing outside this directory is read or
written.
"""

import datetime
import hashlib
import io
import json
import os
import re
import sys
import unittest

sys.dont_write_bytecode = True

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(ROOT, ".agentgov", "evidence")
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "governance-tests.json")
COLLECTOR = "safe-agent.governance-tests"
VALID_DAYS = 90
SUPPORT = "tests/governance/support.py"
AGENT = "triage_agent/agent.py"

# control -> (test module, implementation files, what the tests show)
CONTROLS = {
    "AGC-005": ("test_allowlist", [AGENT, "triage_agent/tools.py"],
                "a tool outside the allowlist is rejected at dispatch and never runs"),
    "AGC-007": ("test_data_isolation", [AGENT, "triage_agent/tools.py", "triage_agent/data.py", "triage_agent/guards.py"],
                "one user cannot read or change another user's records, and the model cannot supply an identity"),
    "AGC-009": ("test_policy", [AGENT, "triage_agent/policy.py"],
                "the policy decides before a tool runs, and a policy engine error is a denial"),
    "AGC-010": ("test_approval", [AGENT, "triage_agent/approval.py", "triage_agent/policy.py"],
                "missing, expired, tampered, denied, mismatched, and replayed approvals are rejected"),
    "AGC-011": ("test_prompt_injection", [AGENT, "triage_agent/guards.py", "triage_agent/tools.py"],
                "instructions injected through tool results cannot trigger unlisted tools or skip approval"),
    "AGC-012": ("test_limits", [AGENT, "triage_agent/limits.py"],
                "the run stops when the step, token, or time limit is reached"),
    "AGC-015": ("test_memory", [AGENT, "triage_agent/memory.py", "triage_agent/tools.py"],
                "memory is isolated per user and tenant and validated before storage"),
    "AGC-017": ("test_killswitch", [AGENT, "triage_agent/killswitch.py"],
                "no action runs after the kill switch is engaged; a run in progress stops within one step"),
    "AGC-018": ("test_idempotency", ["triage_agent/data.py", "triage_agent/tools.py"],
                "a repeated mutating request is applied once, a failed write leaves no partial state, and a close can be compensated"),
    "AGC-022": ("test_tracing", [AGENT, "triage_agent/tracing.py"],
                "a step and its tool call share a run ID and are linked, and sensitive values are redacted"),
    "AGC-023": ("test_audit", ["triage_agent/audit.py"],
                "altered, removed, and reordered audit records are detected"),
}


def subject_digest(root, paths):
    """Same algorithm as evidence.SubjectDigest in the AgentGov scanner.

    For each path in sorted order: the path, a NUL byte, the lowercase hex
    SHA-256 of the file content with CRLF normalized to LF, and a newline.
    The result is the lowercase hex SHA-256 of all of that.
    """
    outer = hashlib.sha256()
    for rel in sorted(set(paths)):
        with open(os.path.join(root, *rel.split("/")), "rb") as handle:
            content = handle.read().replace(b"\r\n", b"\n")
        outer.update(rel.encode("utf-8") + b"\x00" + hashlib.sha256(content).hexdigest().encode("ascii") + b"\n")
    return outer.hexdigest()


def agent_id():
    try:
        with open(os.path.join(ROOT, ".agentgov.yaml"), "r", encoding="utf-8") as handle:
            match = re.search(r"^agent:\s*\n(?:[ \t]+.*\n)*?[ \t]+id:\s*[\"']?([A-Za-z0-9._-]+)", handle.read(), re.M)
        if match:
            return match.group(1)
    except OSError:
        pass
    return "ticket-triage-agent"


def run_module(name, stream):
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.governance." + name)
    return unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)


def timestamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    valid_until = now + datetime.timedelta(days=VALID_DAYS)
    agent = agent_id()
    items = []
    total = failed_total = 0
    all_test_files = set()
    for control in sorted(CONTROLS):
        module, implementation, shows = CONTROLS[control]
        stream = io.StringIO()
        result = run_module(module, stream)
        sys.stdout.write(stream.getvalue())
        bad = len(result.failures) + len(result.errors) + len(result.skipped) + len(result.unexpectedSuccesses)
        passed = result.testsRun > 0 and bad == 0
        total += result.testsRun
        failed_total += bad
        test_file = "tests/governance/" + module + ".py"
        all_test_files.update([test_file, SUPPORT])
        paths = sorted(set(implementation + [test_file, SUPPORT]))
        if passed:
            summary = "%d governance tests passed (%s): %s." % (result.testsRun, module, shows)
        else:
            summary = "%d of %d governance tests did not pass (%s). Expected behavior: %s." % (
                bad, result.testsRun, module, shows)
        items.append({
            "control_id": control,
            "agent_id": agent,
            "source_type": "test",
            "collector": COLLECTOR,
            "observed_at": timestamp(now),
            "valid_until": timestamp(valid_until),
            "result": "pass" if passed else "fail",
            "signal": "present" if passed else "violation",
            "strength": "tested",
            "summary": summary,
            "limitations": [
                "The tests use a scripted model and synthetic data in one process. They do not show how a deployed agent behaves.",
            ],
            "subject": {"paths": paths, "digest": subject_digest(ROOT, paths)},
            "identity_context": "local run of tools/run_governance_tests.py with Python %d.%d" % sys.version_info[:2],
        })
    suite_ok = failed_total == 0 and total > 0
    suite_paths = sorted(all_test_files)
    items.append({
        "control_id": "AGC-020",
        "agent_id": agent,
        "source_type": "test",
        "collector": COLLECTOR,
        "observed_at": timestamp(now),
        "valid_until": timestamp(valid_until),
        "result": "pass" if suite_ok else "fail",
        "signal": "present" if suite_ok else "violation",
        "strength": "tested",
        "summary": ("The governance regression suite ran: %d tests, %d not passing. It covers permitted and forbidden "
                    "tool use, authorization, data separation, and failure modes.") % (total, failed_total),
        "limitations": [
            "One local run. Attach CI run records to show the suite runs on every change.",
        ],
        "subject": {"paths": suite_paths, "digest": subject_digest(ROOT, suite_paths)},
        "identity_context": "local run of tools/run_governance_tests.py with Python %d.%d" % sys.version_info[:2],
    })
    items.sort(key=lambda item: item["control_id"])
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    with open(EVIDENCE_FILE, "w", encoding="utf-8", newline="\n") as handle:
        json.dump({"schema_version": "1", "evidence": items}, handle, indent=2)
        handle.write("\n")
    print("")
    print("Ran %d tests, %d not passing." % (total, failed_total))
    print("Wrote %s (%d items)." % (os.path.relpath(EVIDENCE_FILE, ROOT).replace(os.sep, "/"), len(items)))
    return 0 if suite_ok else 1


if __name__ == "__main__":
    sys.exit(main())
