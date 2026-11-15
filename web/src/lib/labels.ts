// SPDX-License-Identifier: Apache-2.0
//
// Plain-language labels. The wording mirrors internal/reporting/labels.go so
// that the CLI, the HTML report, and the dashboard say the same thing.

export const SCORE_NOTE = "illustrative only";
export const DISCLAIMER = "Evidence-based assessment. Not a certification.";

export function statusLabel(s: string): string {
  switch (s) {
    case "verified-operational":
      return "Verified in operation";
    case "verified-tested":
      return "Verified by tests";
    case "verified-implementation":
      return "Implemented (not yet tested)";
    case "declared-only":
      return "Declared only";
    case "missing":
      return "Missing";
    case "failed":
      return "Failed";
    case "not-applicable":
      return "Not applicable";
    case "accepted-risk":
      return "Accepted risk";
    case "error":
      return "Assessment error";
    default:
      return "Unknown (needs evidence)";
  }
}

export function statusMeaning(s: string): string {
  switch (s) {
    case "verified-operational":
      return "Evidence from the running system shows the control works.";
    case "verified-tested":
      return "A test result shows the control works.";
    case "verified-implementation":
      return "The control exists in the code or configuration. No test result proves it works yet.";
    case "declared-only":
      return "A document or setting says the control exists. Nothing confirms it.";
    case "missing":
      return "The scanner looked for the control and did not find it.";
    case "failed":
      return "The scanner found a concrete problem or a failed test.";
    case "not-applicable":
      return "The control does not apply to this agent. It is left out of the score.";
    case "accepted-risk":
      return "A recorded exception covers this control. It does not count as a pass.";
    case "error":
      return "The check itself did not complete. Run it again or review it by hand.";
    default:
      return "The scanner could not assess the control. More evidence is needed.";
  }
}

export const ALL_STATUSES = [
  "verified-operational",
  "verified-tested",
  "verified-implementation",
  "declared-only",
  "accepted-risk",
  "unknown",
  "missing",
  "failed",
  "error",
  "not-applicable",
] as const;

/** The five summary groups used for color and icon shape. */
export type Rollup = "verified" | "partial" | "unknown" | "failed" | "na";

export function rollupOf(s: string): Rollup {
  switch (s) {
    case "verified-operational":
    case "verified-tested":
      return "verified";
    case "verified-implementation":
    case "declared-only":
    case "accepted-risk":
      return "partial";
    case "failed":
    case "missing":
    case "error":
      return "failed";
    case "not-applicable":
      return "na";
    default:
      return "unknown";
  }
}

export function rollupLabel(r: Rollup): string {
  switch (r) {
    case "verified":
      return "Verified";
    case "partial":
      return "Partial";
    case "failed":
      return "Failed";
    case "na":
      return "Not applicable";
    default:
      return "Unknown";
  }
}

export function rollupMeaning(r: Rollup): string {
  switch (r) {
    case "verified":
      return "Test or operational evidence shows the control works.";
    case "partial":
      return "The control is implemented or declared but not proven by tests, or a recorded exception covers it.";
    case "failed":
      return "The control failed, is missing, or could not be checked because of an error.";
    case "na":
      return "The control does not apply and is left out of the score.";
    default:
      return "There is not enough evidence to assess the control.";
  }
}

export const ROLLUPS: Rollup[] = ["verified", "partial", "unknown", "failed", "na"];

export type DecisionKey = "allow" | "block" | "review" | "unknown";

export function decisionKey(o: string): DecisionKey {
  switch (o) {
    case "ALLOW":
      return "allow";
    case "BLOCK":
      return "block";
    case "REVIEW_REQUIRED":
      return "review";
    default:
      return "unknown";
  }
}

export function decisionName(o: string): string {
  switch (o) {
    case "ALLOW":
      return "ALLOW";
    case "BLOCK":
      return "BLOCK";
    case "REVIEW_REQUIRED":
      return "REVIEW REQUIRED";
    default:
      return "UNDETERMINED";
  }
}

export function decisionExplanation(o: string): string {
  switch (o) {
    case "ALLOW":
      return "The release policy is satisfied.";
    case "BLOCK":
      return "Do not release until the listed controls are fixed.";
    case "REVIEW_REQUIRED":
      return "A person must review before release.";
    default:
      return "The decision could not be read, so do not treat this as a pass.";
  }
}

export function decisionLabel(o: string): string {
  const e = decisionExplanation(o);
  return `${decisionName(o)}: ${e.charAt(0).toLowerCase()}${e.slice(1, -1)}`;
}

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export function severityRank(s: string): number {
  const i = (SEVERITIES as readonly string[]).indexOf(s);
  return i < 0 ? SEVERITIES.length : i;
}

export function severityLabel(s: string): string {
  switch (s) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    case "info":
      return "Info";
    default:
      return "Unrated";
  }
}

export function sourceTypeLabel(s: string): string {
  switch (s) {
    case "static":
      return "Static scan";
    case "configuration":
      return "Configuration";
    case "test":
      return "Test result";
    case "runtime":
      return "Runtime record";
    case "external-attestation":
      return "External attestation";
    case "manual-review":
      return "Manual review";
    default:
      return "Unknown source";
  }
}

export function validityLabel(v: string): string {
  switch (v) {
    case "valid":
      return "Valid";
    case "expired":
      return "Expired";
    case "commit-mismatch":
      return "Bound to a different commit";
    case "digest-mismatch":
      return "Files changed since collection";
    case "unbound":
      return "Not bound to a commit or digest";
    case "invalid-signature":
      return "Signature did not verify";
    case "malformed":
      return "Malformed";
    default:
      return "Unknown validity";
  }
}

export function integrityLabel(i: string): string {
  switch (i) {
    case "verified":
      return "Signature verified";
    case "unsigned":
      return "Unsigned";
    case "invalid":
      return "Signature invalid";
    case "not-available":
      return "Observed by the scanner";
    default:
      return "Unknown integrity";
  }
}

export function strengthLabel(s: string): string {
  switch (s) {
    case "declared":
      return "Declared (level 1)";
    case "implementation":
      return "Implementation (level 2)";
    case "tested":
      return "Tested (level 3)";
    case "operational":
      return "Operational (level 4)";
    default:
      return "Unknown strength";
  }
}

export function maturityName(n: number): string {
  switch (n) {
    case 4:
      return "verified in operation";
    case 3:
      return "verified by tests";
    case 2:
      return "implemented";
    case 1:
      return "declared";
    default:
      return "no credited evidence";
  }
}

export function profileSourceLabel(src: string): string {
  switch (src) {
    case "flag":
      return "set on the command line";
    case "config":
      return "set in the configuration file";
    case "baseline-lock":
      return "locked by the organization baseline";
    case "inferred":
      return "inferred from the detected capabilities";
    case "default":
      return "default profile";
    case "":
      return "source not recorded";
    default:
      return src;
  }
}

export function basisLabel(b: string): string {
  switch (b) {
    case "always":
      return "Applies to every agent";
    case "detected":
      return "A capability that this control governs was detected";
    case "declared":
      return "The configuration declares the capability";
    case "inferred":
      return "Inferred: no triggering capability was detected. This is not an approval.";
    case "approved":
      return "Not applicable, approved with a recorded reason";
    default:
      return b || "Not recorded";
  }
}

export function projectRoleLabel(r: string | undefined): string {
  switch (r) {
    case "administrator":
      return "Administrator";
    case "owner":
      return "Owner";
    case "reviewer":
      return "Reviewer";
    case "viewer":
      return "Viewer";
    case "user":
      return "User";
    default:
      return "Member";
  }
}

/** Shows an explicit "unknown" value as a readable phrase. */
export function orUnknown(v: string | null | undefined, what = "Not declared"): string {
  if (!v || v === "unknown") return what;
  return v;
}

export const NO_AGENT_TITLE = "No AI agent was detected";
export const NO_AGENT_LINES = [
  "Discovery looks for agent framework imports, tool definitions, MCP server or client configuration, and model client calls in Python, TypeScript, and JavaScript files.",
  "This is not a pass. No control was assessed, so there is no score.",
  "If this repository contains an agent, declare it: run agentgov init, fill in the generated .agentgov.yaml file, and scan again.",
];
