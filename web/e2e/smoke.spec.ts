// SPDX-License-Identifier: Apache-2.0
//
// Smoke test of the built dashboard, served by the real Go server with its
// Content-Security-Policy. It runs as one serial story on one page:
// setup -> onboarding and real uploads -> overview -> agent -> control ->
// findings -> compare -> token shown once -> sign-out.
//
// Environment:
//   AGENTGOV_URL              server address (default http://127.0.0.1:8090)
//   AGENTGOV_BOOTSTRAP_TOKEN  one-time token of a fresh server (first run only)
//   E2E_USER, E2E_PASSWORD    administrator account to create or to sign in with
//   AGENTGOV_BIN              CLI binary (default <repo>/bin/agentgov[.exe])

import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import {
  BOOTSTRAP_TOKEN,
  EXAMPLES_PROJECT,
  expectClean,
  openAgent,
  openProject,
  PASSWORD,
  signIn,
  uploadScan,
  USERNAME,
  VULNERABLE_AGENT,
  VULNERABLE_PROJECT,
  watch,
  type Problems,
} from "./helpers";

test.describe.configure({ mode: "serial" });

let page: Page;
let problems: Problems;
let freshServer = false;

test.beforeAll(async ({ browser, request }) => {
  expect(PASSWORD.length, "set E2E_PASSWORD (12 or more characters)").toBeGreaterThanOrEqual(12);
  const v = await (await request.get("/api/v1/version")).json();
  freshServer = v.setup_required === true;
  if (freshServer) expect(BOOTSTRAP_TOKEN, "set AGENTGOV_BOOTSTRAP_TOKEN for a fresh server").not.toBe("");
  page = await browser.newPage();
  problems = await watch(page);
});

test.afterAll(async () => {
  await page.close();
});

test.afterEach(() => {
  expectClean(problems);
});

/** Creates a token in the connect guide, checks it is shown once, and returns it. */
async function createTokenInGuide(): Promise<string> {
  await page.getByRole("button", { name: "Create token" }).click();
  const reveal = page.getByTestId("token-reveal");
  await expect(reveal).toBeVisible();
  const token = (await page.getByTestId("token-value").innerText()).trim();
  expect(token).toMatch(/^agt_[0-9a-f]{8}_/);
  await reveal.getByRole("button", { name: "I have saved it" }).click();
  await expect(reveal).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(token);
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
  expect(stored).not.toContain("agt_");
  return token;
}

test("first-run setup, or sign-in on a server that is already set up", async () => {
  if (!freshServer) {
    await signIn(page, problems);
    return;
  }
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { level: 1, name: "Set up this server" })).toBeVisible();
  await expect(page.getByText("At least 12 characters.")).toBeVisible();
  if (process.env.SCREENSHOT_DIR) {
    // Taken before anything is typed, so the picture holds no secret.
    await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, "dashboard-setup.png"), animations: "disabled" });
  }

  // The password rule is enforced before anything is sent.
  await page.getByLabel("Bootstrap token", { exact: true }).fill(BOOTSTRAP_TOKEN);
  await page.getByLabel("Administrator username").fill(USERNAME);
  const pw = page.getByLabel("Password", { exact: true });
  await pw.fill("short");
  await expect(page.getByText("7 more to go.")).toBeVisible();
  await pw.fill(PASSWORD);
  await expect(page.getByText("Long enough.")).toBeVisible();

  // Show and hide toggle.
  await expect(pw).toHaveAttribute("type", "password");
  await page.getByRole("button", { name: "Show password" }).click();
  await expect(pw).toHaveAttribute("type", "text");
  await page.getByRole("button", { name: "Hide password" }).click();
  await expect(pw).toHaveAttribute("type", "password");

  await page.getByRole("button", { name: "Create administrator and sign in" }).click();
  await expect(page.getByTestId("user-name")).toHaveText(USERNAME);
  await expect(page.getByText("Evidence-based assessment. Not a certification.")).toBeVisible();
});

test("onboarding: project, token shown once, real uploads, connection check", async () => {
  test.skip(!freshServer, "the server already holds data");
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Connect your first repository" })).toBeVisible();

  await page.getByLabel("Project name").fill(VULNERABLE_PROJECT);
  await expect(page.getByLabel("Short ID")).toHaveValue("vulnerable-example");
  await page.getByRole("button", { name: "Create project" }).click();
  await expect(page.getByLabel("Project", { exact: true })).toContainText(VULNERABLE_PROJECT);

  // Before any upload the check must say that nothing arrived.
  await page.getByRole("button", { name: "Check connection" }).click();
  await expect(page.getByText("No scan has arrived yet")).toBeVisible();

  const token = await createTokenInGuide();
  await expect(page.getByText("PowerShell (Windows)")).toBeVisible();
  await expect(page.getByText(`agentgov scan . --upload-url ${new URL(page.url()).origin}`).first()).toBeVisible();

  // Two uploads of the same agent with different profiles: these are not comparable.
  uploadScan("vulnerable-agent", token);
  uploadScan("vulnerable-agent", token, ["--profile", "high-risk"]);

  await page.getByRole("button", { name: "Check connection" }).click();
  await expect(page.getByText("Connected. The first scan arrived.")).toBeVisible();
  await page.getByRole("link", { name: "Open the project" }).click();
  await expect(page.getByRole("heading", { level: 1, name: VULNERABLE_PROJECT })).toBeVisible();

  // Second project through the Projects page.
  await page.goto("/projects");
  await page.getByLabel("Project name").fill(EXAMPLES_PROJECT);
  await page.getByRole("button", { name: "Create project" }).click();
  await expect(page).toHaveURL(/\/connect\?project=/);
  await expect(page.getByLabel("Project", { exact: true })).toContainText(EXAMPLES_PROJECT);
  const token2 = await createTokenInGuide();
  uploadScan("safe-agent", token2);
  uploadScan("typescript-agent", token2);
  uploadScan("python-langgraph", token2);
  await page.getByRole("button", { name: "Check connection" }).click();
  await expect(page.getByText("Connected. The first scan arrived.")).toBeVisible();
});

test("overview: plain headline and project cards from the API", async () => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await expect(page.getByTestId("headline")).toHaveText(/^\d+ of \d+ agents? (is|are) blocked from release$/);
  await expect(page.locator(".project-card")).toHaveCount(2);
  await expect(page.locator(".project-card", { hasText: VULNERABLE_PROJECT })).toContainText("critical");
  await expect(page.getByText("Evidence-based assessment. Not a certification.")).toBeVisible();
});

test("agent inventory: sort and filter", async () => {
  await openProject(page, EXAMPLES_PROJECT);
  const rows = page.locator("table tbody tr");
  await expect(rows).toHaveCount(3);
  await page.getByLabel("Decision", { exact: true }).selectOption("allow");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("ALLOW");
  await page.getByLabel("Decision", { exact: true }).selectOption("");
  await page.getByLabel("Search agents").fill("langgraph");
  await expect(rows).toHaveCount(1);
  await page.getByLabel("Search agents").fill("");
  const score = page.getByRole("columnheader", { name: "Score" });
  await score.getByRole("button").click();
  await expect(score).toHaveAttribute("aria-sort", "ascending");
});

test("agent detail: decision banner, 24 control tiles, score note, history break", async () => {
  await openAgent(page, VULNERABLE_PROJECT, VULNERABLE_AGENT);
  const banner = page.getByTestId("decision-banner");
  await expect(banner).toContainText("BLOCK");
  await expect(banner).toContainText("Do not release until the listed controls are fixed.");
  await expect(page.getByTestId("control-tile")).toHaveCount(24);
  await expect(page.locator(".domain")).toHaveCount(6);
  await expect(page.getByText("illustrative only", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What blocks release" })).toBeVisible();
  await expect(page.locator(".blocker").first()).toContainText("Next action:");
  await expect(page.getByRole("heading", { name: "Evidence freshness" })).toBeVisible();
  // Two scans with different profiles must not be joined into a trend.
  await expect(page.getByText("Not comparable: policy changed.")).toBeVisible();
  await expect(page.locator(".history-line")).toHaveCount(0);
});

test("control detail: status, evidence, references, and deep-link reload", async () => {
  await openAgent(page, VULNERABLE_PROJECT, VULNERABLE_AGENT);
  await page.getByTestId("control-tile").filter({ hasText: "AGC-008" }).click();
  await expect(page).toHaveURL(/\/scans\/[^/]+\/controls\/AGC-008\?agent=/);
  const status = page.getByTestId("control-status");
  await expect(status).toContainText("Exact reason:");
  for (const h of [/^Evidence \(\d+\)$/, "How it was assessed", "Limitations", "How to fix it", /^Related findings/, "Standards references"]) {
    await expect(page.getByRole("heading", { name: h })).toBeVisible();
  }
  await expect(page.getByText("Reference only, not certification")).toBeVisible();
  const links = page.locator("a.ext-link");
  expect(await links.count()).toBeGreaterThan(0);
  for (const a of await links.all()) {
    await expect(a).toHaveAttribute("rel", "noopener noreferrer");
  }
  // The server falls back to index.html for a client-side route.
  await page.reload();
  await expect(page.getByTestId("control-status")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("AGC-008");
});

test("findings: filter by severity and text, then open a finding", async () => {
  await openAgent(page, VULNERABLE_PROJECT, VULNERABLE_AGENT);
  await page.getByRole("link", { name: /^Findings \(\d+\)$/ }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Findings" })).toBeVisible();
  const rows = page.locator("table tbody tr");
  const all = await rows.count();
  expect(all).toBeGreaterThan(5);

  await page.getByLabel("Severity").selectOption("critical");
  await expect(page).toHaveURL(/severity=critical/);
  await expect(page.getByTestId("findings-count")).toContainText(/^Showing \d+ of \d+ findings/);
  const critical = await rows.count();
  expect(critical).toBeGreaterThan(0);
  expect(critical).toBeLessThan(all);
  for (const r of await rows.all()) await expect(r).toContainText("Critical");

  await page.getByLabel("Search findings").fill("zzz-no-such-finding");
  await expect(page.getByText("No finding matches these filters.")).toBeVisible();
  await page.getByRole("button", { name: "Clear filters" }).click();
  await expect(rows).toHaveCount(all);

  await page.getByLabel("Severity").selectOption("critical");
  await rows.first().getByRole("link").first().click();
  await expect(page).toHaveURL(/\/findings\/F-/);
  for (const h of ["What was found", "Why it matters", "How to fix it", "Details"]) {
    await expect(page.getByRole("heading", { name: h })).toBeVisible();
  }
  await expect(page.getByTestId("finding-location")).toContainText(/\w+\.\w+:\d+/);
  await page.getByTestId("finding-control-link").click();
  await expect(page.getByTestId("control-status")).toBeVisible();
});

test("compare: non-comparable scans hide the score change", async () => {
  await openAgent(page, VULNERABLE_PROJECT, VULNERABLE_AGENT);
  await page.getByRole("link", { name: "Compare scans" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Compare scans" })).toBeVisible();
  await expect(page.getByTestId("not-comparable")).toContainText("Not comparable: policy changed");
  await expect(page.getByTestId("not-comparable")).toContainText("profile differs");
  await expect(page.getByTestId("score-change")).toHaveCount(0);
  for (const h of [/^New findings \(\d+\)$/, /^Resolved findings \(\d+\)$/, /^Unchanged findings \(\d+\)$/, /^Control changes \(\d+\)$/]) {
    await expect(page.getByRole("heading", { name: h })).toBeVisible();
  }
});

test("reference pages and audit events load", async () => {
  await page.goto("/controls");
  await expect(page.locator(".catalog-item")).toHaveCount(24);
  await page.goto("/policies");
  await expect(page.getByRole("heading", { name: "Which controls each profile requires" })).toBeVisible();
  await page.goto("/audit");
  await expect(page.locator("table tbody tr").first()).toContainText(/\w+\.\w+/);
  await page.goto("/no-such-page");
  await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
});

test("a new upload token is shown once and then only as a prefix", async () => {
  await openProject(page, EXAMPLES_PROJECT);
  await page.getByRole("tab", { name: "Upload tokens" }).click();
  const name = `e2e-${Date.now()}`;
  await page.getByLabel("Token name").fill(name);
  await page.getByRole("button", { name: "Create token" }).click();
  const reveal = page.getByTestId("token-reveal");
  await expect(reveal).toBeVisible();
  const token = (await page.getByTestId("token-value").innerText()).trim();
  expect(token).toMatch(/^agt_[0-9a-f]{8}_.{20,}$/);
  await expect(reveal.getByRole("button", { name: "Copy token" })).toBeVisible();
  await reveal.getByRole("button", { name: "Dismiss the token panel" }).click();
  await expect(reveal).toHaveCount(0);

  const row = page.locator("table tbody tr", { hasText: name });
  await expect(row).toContainText(`${token.slice(0, 13)}…`);
  await expect(page.locator("body")).not.toContainText(token);
  await page.reload();
  await expect(page.locator("table tbody tr", { hasText: name })).toBeVisible();
  await expect(page.locator("body")).not.toContainText(token);
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
  expect(stored).not.toContain("agt_");

  // Revoke it again so that the test leaves no usable token behind.
  await page.getByRole("button", { name: `Revoke token ${name}` }).click();
  await page.getByRole("button", { name: `Revoke “${name}” now` }).click();
  await expect(page.locator("table tbody tr", { hasText: name })).toContainText("Revoked");
});

test("phone width: no horizontal overflow, and the menu opens", async () => {
  await openAgent(page, VULNERABLE_PROJECT, VULNERABLE_AGENT);
  const agentUrl = page.url();
  await page.getByTestId("control-tile").filter({ hasText: "AGC-008" }).click();
  await expect(page.getByTestId("control-status")).toBeVisible();
  const controlUrl = page.url();
  await page.goto(agentUrl);
  await page.getByRole("link", { name: /^Findings \(\d+\)$/ }).click();
  await expect(page.getByTestId("findings-count")).toBeVisible();
  const findingsUrl = page.url();

  await page.setViewportSize({ width: 375, height: 720 });
  for (const url of ["/", "/projects", agentUrl, controlUrl, findingsUrl, `${agentUrl}/compare`, "/connect", "/controls", "/policies"]) {
    await page.goto(url);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.waitForLoadState("networkidle");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, `horizontal overflow on ${url}`).toBeLessThanOrEqual(0);
  }
  await page.getByRole("button", { name: "Open menu" }).click();
  await expect(page.getByRole("link", { name: "Controls catalog" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("link", { name: "Controls catalog" })).toBeHidden();
  await page.setViewportSize({ width: 1440, height: 900 });
});

test("theme toggle is remembered", async () => {
  await page.goto("/");
  await page.getByRole("button", { name: "Switch to dark theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});

test("sign-out, generic error for a wrong password, and sign-in again", async () => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);

  // A protected page sends a signed-out visitor to the sign-in screen.
  problems.expected.add("401 /api/v1/session");
  problems.expected.add("401 /api/v1/login");
  await page.goto("/projects");
  await expect(page).toHaveURL(/\/login$/);

  await page.getByLabel("Username").fill(USERNAME);
  await page.getByLabel("Password", { exact: true }).fill("wrong-password-123");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("The username or the password is not correct.")).toBeVisible();

  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  // Sign-in returns to the page that was asked for.
  await expect(page).toHaveURL(/\/projects$/);
  await expect(page.getByTestId("user-name")).toHaveText(USERNAME);
  problems.expected.clear();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
});

test("a viewer sees explanations instead of management actions, and no other project", async () => {
  await signIn(page, problems);
  await openProject(page, VULNERABLE_PROJECT);
  const otherProjectPath = new URL(page.url()).pathname;

  // The administrator creates a user and adds it to one project as a viewer.
  const viewer = `viewer-${Date.now()}`;
  const viewerPassword = `${PASSWORD}-viewer`;
  await page.goto("/users");
  await page.getByLabel("Username").fill(viewer);
  await page.getByLabel("Password", { exact: true }).fill(viewerPassword);
  await page.getByRole("button", { name: "Create user" }).click();
  await expect(page.locator("table tbody tr", { hasText: viewer })).toContainText("User");

  await openProject(page, EXAMPLES_PROJECT);
  await page.getByRole("tab", { name: "Members" }).click();
  await page.getByLabel("Username").fill(viewer);
  await page.getByLabel("Role", { exact: true }).selectOption("viewer");
  await page.getByRole("button", { name: "Save member" }).click();
  await expect(page.locator("table tbody tr", { hasText: viewer })).toContainText("Viewer");
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);

  await signIn(page, problems, viewer, viewerPassword);
  await expect(page.getByRole("link", { name: "Users" })).toHaveCount(0);
  await page.goto("/projects");
  await expect(page.locator("table tbody tr")).toHaveCount(1);
  await expect(page.getByText("Only an administrator can create a project")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create project" })).toHaveCount(0);

  await page.getByRole("link", { name: EXAMPLES_PROJECT, exact: true }).click();
  await expect(page.locator("table tbody tr")).toHaveCount(3);
  await page.getByRole("tab", { name: "Upload tokens" }).click();
  await expect(page.getByText("Only project owners and administrators can manage upload tokens")).toBeVisible();
  await page.getByRole("tab", { name: "Members" }).click();
  await expect(page.getByText("Only project owners and administrators can manage members")).toBeVisible();

  await page.goto("/audit");
  await expect(page.getByText("Your role cannot see audit events")).toBeVisible();

  // A project the viewer is not a member of answers 404, the same as a missing project.
  problems.expected.add(`404 ${otherProjectPath}`);
  await page.goto(otherProjectPath);
  await expect(page.getByText("Not found, or you do not have access")).toBeVisible();
  problems.expected.clear();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
});
