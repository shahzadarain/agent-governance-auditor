// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { AgentScan, Evidence } from "../api/types";
import { groupByDomain, splitDomain } from "./data";
import { absoluteTime, evidenceFreshness, historySegments, relativeTime, shortCommit } from "./format";
import { ALL_STATUSES, decisionExplanation, decisionLabel, decisionName, rollupOf, statusLabel, statusMeaning } from "./labels";

describe("labels match the CLI and the HTML report", () => {
  it("names every status in plain language", () => {
    expect(statusLabel("verified-operational")).toBe("Verified in operation");
    expect(statusLabel("verified-implementation")).toBe("Implemented (not yet tested)");
    expect(statusLabel("unknown")).toBe("Unknown (needs evidence)");
    // A status this build does not know is never shown as a pass.
    expect(statusLabel("brand-new-status")).toBe("Unknown (needs evidence)");
    expect(rollupOf("brand-new-status")).toBe("unknown");
    for (const s of ALL_STATUSES) expect(statusMeaning(s)).toMatch(/\.$/);
  });

  it("groups statuses into five roll-ups", () => {
    expect(rollupOf("verified-tested")).toBe("verified");
    expect(rollupOf("accepted-risk")).toBe("partial");
    expect(rollupOf("error")).toBe("failed");
    expect(rollupOf("missing")).toBe("failed");
    expect(rollupOf("not-applicable")).toBe("na");
  });

  it("explains each decision", () => {
    expect(decisionName("REVIEW_REQUIRED")).toBe("REVIEW REQUIRED");
    expect(decisionLabel("BLOCK")).toBe("BLOCK: do not release until the listed controls are fixed");
    expect(decisionLabel("ALLOW")).toBe("ALLOW: the release policy is satisfied");
    expect(decisionExplanation("REVIEW_REQUIRED")).toBe("A person must review before release.");
    expect(decisionName("")).toBe("UNDETERMINED");
    expect(decisionExplanation("something-else")).toContain("do not treat this as a pass");
  });
});

describe("format", () => {
  const now = new Date("2026-11-15T12:00:00Z");
  it("formats relative and absolute time", () => {
    expect(relativeTime("2026-11-15T11:59:50Z", now)).toBe("just now");
    expect(relativeTime("2026-11-15T09:00:00Z", now)).toBe("3 hours ago");
    expect(relativeTime("2026-11-18T12:00:00Z", now)).toBe("in 3 days");
    expect(relativeTime("not a date", now)).toBe("");
    expect(absoluteTime("2026-11-15T09:00:00.123Z")).toBe("2026-11-15 09:00:00 UTC");
    expect(shortCommit("unknown")).toBe("no commit");
    expect(shortCommit("4f9c2d7a1b3e5f60")).toBe("4f9c2d7a");
  });

  const scan = (id: string, at: string, profile: string, version = "1.0"): AgentScan => ({
    id,
    scan_id: id,
    received_at: at,
    commit_sha: "abc",
    profile,
    policy_pack: "builtin/v1",
    policy_version: version,
    tool_version: "0.1.0",
    decision: "BLOCK",
    score: 10,
    score_label: "10/100",
  });

  it("never joins scans across a policy or profile change", () => {
    const segs = historySegments([
      scan("c", "2026-11-03T00:00:00Z", "high-risk"),
      scan("a", "2026-11-01T00:00:00Z", "standard"),
      scan("b", "2026-11-02T00:00:00Z", "standard"),
      scan("d", "2026-11-04T00:00:00Z", "high-risk", "1.1"),
      scan("e", "2026-11-05T00:00:00Z", "standard"),
    ]);
    expect(segs.map((s) => s.points.map((p) => p.id).join(""))).toEqual(["ab", "c", "d", "e"]);
  });

  it("summarizes evidence freshness", () => {
    const ev = (validity: string, valid_until: string | null): Evidence =>
      ({ validity, valid_until, evidence_id: Math.random().toString() }) as Evidence;
    const f = evidenceFreshness([
      ev("valid", "2027-01-01T00:00:00Z"),
      ev("valid", "2026-12-01T00:00:00Z"),
      ev("valid", null),
      ev("expired", "2026-01-01T00:00:00Z"),
      ev("commit-mismatch", null),
    ]);
    expect(f).toMatchObject({ total: 5, valid: 3, expired: 1, otherInvalid: 1, noExpiry: 1, nextExpiry: "2026-12-01T00:00:00Z" });
  });
});

describe("domains", () => {
  it("groups controls by domain in order", () => {
    const g = groupByDomain([
      { domain: "B: Identity and Access", id: 1 },
      { domain: "A: Accountability", id: 2 },
      { domain: "B: Identity and Access", id: 3 },
    ]);
    expect(g.map((x) => `${splitDomain(x.domain).letter}${x.items.length}`)).toEqual(["A1", "B2"]);
    expect(splitDomain("No letter")).toEqual({ letter: "", name: "No letter" });
  });
});
