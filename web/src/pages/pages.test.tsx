// SPDX-License-Identifier: Apache-2.0
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import type { ControlResult, Finding } from "../api/types";
import { DecisionChip, ErrorState, MaturityBar, StatusBadge } from "../components/ui";
import { slugify } from "../components/forms";
import { scanCommands } from "../components/ConnectGuide";
import { detailText } from "./Admin";
import { ControlGrid } from "./AgentDetail";
import { forAgent } from "./Compare";
import { safeHttpUrl, StandardsList } from "./ControlDetail";
import { matchesText } from "./Findings";
import { loginErrorText } from "./Login";
import { countDecisions, headline } from "./Overview";

afterEach(cleanup);

describe("overview headline", () => {
  it("puts blocked agents first", () => {
    expect(headline(countDecisions({ BLOCK: 2, ALLOW: 2, REVIEW_REQUIRED: 1 })).text).toBe("2 of 5 agents are blocked from release");
    expect(headline(countDecisions({ BLOCK: 1 })).text).toBe("1 of 1 agent is blocked from release");
  });
  it("covers review, allow, unknown, and empty", () => {
    expect(headline(countDecisions({ REVIEW_REQUIRED: 1, ALLOW: 3 }))).toEqual({ text: "1 of 4 agents needs a review before release", tone: "review" });
    expect(headline(countDecisions({ ALLOW: 3 }))).toEqual({ text: "All 3 agents meet their release policy", tone: "allow" });
    expect(headline(countDecisions({ "": 1, ALLOW: 1 })).tone).toBe("unknown");
    expect(headline(countDecisions(null)).text).toBe("No agents have been assessed yet");
  });
});

describe("status is never shown by color alone", () => {
  it("gives every chip a text label and an icon", () => {
    render(
      <>
        <DecisionChip decision="BLOCK" />
        <DecisionChip decision="garbage" />
        <StatusBadge status="failed" />
        <MaturityBar value={2} required={3} />
      </>,
    );
    expect(screen.getByText("BLOCK").querySelector("svg")).not.toBeNull();
    expect(screen.getByText("UNDETERMINED")).toBeTruthy();
    expect(screen.getByText("Failed")).toBeTruthy();
    expect(screen.getByRole("img", { name: "Maturity 2 of 4, required 3" })).toBeTruthy();
  });
});

const control = (n: number, over: Partial<ControlResult> = {}): ControlResult => ({
  control_id: `AGC-${String(n).padStart(3, "0")}`,
  agent_id: "agent-a",
  title: `Control ${n}`,
  domain: ["A: Accountability", "B: Identity and Access", "C: Action Controls", "D: Trust Boundaries", "E: Containment and Recovery", "F: Assurance and Visibility"][n % 6]!,
  plain_language: "",
  status: "unknown",
  status_reason: "",
  maturity: 0,
  max_static_maturity: 2,
  applicable: true,
  applicability_basis: "always",
  applicability_reason: "",
  mandatory: false,
  min_maturity: 0,
  weight: 1,
  severity: "medium",
  evidence_refs: [],
  finding_refs: [],
  next_action: "",
  remediation: [],
  limitations: [],
  ...over,
});

describe("control grid", () => {
  it("renders 24 tiles in six domains with status, maturity, and the mandatory mark", () => {
    const controls = Array.from({ length: 24 }, (_, i) => control(i + 1));
    controls[0] = control(1, { status: "failed", mandatory: true, min_maturity: 2 });
    render(
      <MemoryRouter>
        <ControlGrid controls={controls} scanId="scn_1" />
      </MemoryRouter>,
    );
    expect(screen.getAllByTestId("control-tile")).toHaveLength(24);
    expect(screen.getAllByRole("region")).toHaveLength(6);
    const tile = screen.getByText("AGC-001").closest("a")!;
    expect(tile.getAttribute("href")).toBe("/scans/scn_1/controls/AGC-001?agent=agent-a");
    expect(within(tile).getByText("Failed")).toBeTruthy();
    expect(within(tile).getByText("Mandatory")).toBeTruthy();
    expect(within(tile).getByText("Below required level")).toBeTruthy();
    expect(within(tile).getByRole("img", { name: "Maturity 0 of 4, required 2" })).toBeTruthy();
  });
});

describe("untrusted strings", () => {
  it("links only http and https references, with rel noopener noreferrer", () => {
    expect(safeHttpUrl("javascript:alert(1)")).toBeNull();
    expect(safeHttpUrl("data:text/html,x")).toBeNull();
    expect(safeHttpUrl("not a url")).toBeNull();
    expect(safeHttpUrl("https://genai.owasp.org/x")).toBe("https://genai.owasp.org/x");
    render(
      <StandardsList
        mappings={[
          { standard: "OWASP", version: "2025", requirement_id: "LLM06", url: "https://genai.owasp.org/x", rationale: "<img src=x onerror=alert(1)>" },
          { standard: "Bad", version: "1", requirement_id: "X", url: "javascript:alert(1)", rationale: "r" },
        ]}
      />,
    );
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(1);
    expect(links[0]!.getAttribute("rel")).toBe("noopener noreferrer");
    expect(screen.getByText("Reference only, not certification")).toBeTruthy();
    // Server text is rendered as text, never as markup.
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("shows audit detail as text", () => {
    expect(detailText({ slug: "a", n: 2, nested: { x: 1 } })).toBe('slug: a, n: 2, nested: {"x":1}');
    expect(detailText({})).toBe("");
  });
});

describe("errors and helpers", () => {
  it("explains 404 as missing or not permitted", () => {
    render(
      <MemoryRouter>
        <ErrorState error={new ApiError(404, "not_found", "The requested resource does not exist.")} />
      </MemoryRouter>,
    );
    expect(screen.getByText("Not found, or you do not have access")).toBeTruthy();
  });
  it("offers a retry for other errors", () => {
    render(
      <MemoryRouter>
        <ErrorState error={new ApiError(500, "internal_error", "Internal server error.")} onRetry={() => {}} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
  it("keeps sign-in errors generic and reports rate limits", () => {
    expect(loginErrorText(new ApiError(401, "invalid_credentials", "Invalid username or password."))).toBe("The username or the password is not correct.");
    expect(loginErrorText(new ApiError(429, "rate_limited", "x", 30))).toBe("Too many sign-in attempts. Wait 30 seconds, then try again.");
  });
  it("builds slugs and scan commands", () => {
    expect(slugify("  Payments Platform (EU) ")).toBe("payments-platform-eu");
    const c = scanCommands("https://agentgov.example");
    expect(c.powershell).toContain("$env:AGENTGOV_TOKEN");
    expect(c.bash).toContain("agentgov scan . --upload-url https://agentgov.example");
    expect(c.bash).not.toMatch(/agt_/);
  });
  it("filters findings by text and by agent", () => {
    const f = (over: Partial<Finding>): Finding =>
      ({ finding_id: "F-1", fingerprint: "p1", title: "A secret is written directly in a file", description: "", rule_id: "AGC-008.hardcoded-secret", control_id: "AGC-008", agent_id: "a", severity: "critical", why_it_matters: "", ...over }) as Finding;
    expect(matchesText(f({}), "SECRET")).toBe(true);
    expect(matchesText(f({ location: { path: "src/agent.py", line: 3 } }), "agent.py")).toBe(true);
    expect(matchesText(f({}), "sandbox")).toBe(false);
    const list = forAgent([f({ agent_id: "b" }), f({ agent_id: "*", severity: "low", title: "Repo" }), f({})], "a");
    expect(list.map((x) => x.agent_id)).toEqual(["a", "*"]);
  });
});
