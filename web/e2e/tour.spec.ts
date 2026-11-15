// SPDX-License-Identifier: Apache-2.0
//
// Takes the documentation screenshots from the running app. It runs only
// when SCREENSHOT_DIR is set, after smoke.spec.ts has filled the server with
// the real example scans. No token is ever on screen in these pictures.

import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { expectClean, openAgent, signIn, VULNERABLE_AGENT, VULNERABLE_PROJECT, watch } from "./helpers";

const DIR = process.env.SCREENSHOT_DIR ?? "";

test.skip(DIR === "", "set SCREENSHOT_DIR to take screenshots");

async function shot(page: Page, name: string, fullPage = false): Promise<void> {
  // Let fonts, layout observers, and the history chart settle.
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(250);
  await page.screenshot({ path: path.join(DIR, name), fullPage, animations: "disabled" });
}

test("screenshots for the documentation", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light", deviceScaleFactor: 1 });
  const page = await context.newPage();
  const problems = await watch(page);
  await signIn(page, problems);

  await page.goto("/");
  await expect(page.getByTestId("headline")).toBeVisible();
  await shot(page, "dashboard-overview.png");

  await openAgent(page, VULNERABLE_PROJECT, VULNERABLE_AGENT);
  const agentUrl = page.url();
  await expect(page.locator(".history-svg")).toBeVisible();
  await shot(page, "dashboard-agent.png");
  await page.getByRole("heading", { name: "The 24 controls" }).scrollIntoViewIfNeeded();
  await page.evaluate(() => {
    const el = document.querySelector(".controls-card");
    if (el) window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY - 76);
  });
  await page.waitForTimeout(250);
  await page.screenshot({ path: path.join(DIR, "dashboard-controls.png"), animations: "disabled" });

  await page.getByTestId("control-tile").filter({ hasText: "AGC-008" }).click();
  await expect(page.getByTestId("control-status")).toBeVisible();
  await shot(page, "dashboard-control.png");

  await page.goto(agentUrl);
  await page.getByRole("link", { name: /^Findings \(\d+\)$/ }).click();
  await expect(page.getByTestId("findings-count")).toBeVisible();
  await shot(page, "dashboard-findings.png");

  await page.goto(agentUrl);
  await page.getByRole("link", { name: "Compare scans" }).click();
  await expect(page.getByRole("heading", { name: /^Unchanged findings/ })).toBeVisible();
  await shot(page, "dashboard-compare.png");

  await page.goto("/connect");
  await expect(page.getByRole("heading", { name: "Check the connection" })).toBeVisible();
  // The guide is taller than 900px. Grow the window so that all four steps are in one picture.
  const guideHeight = await page.evaluate(() => document.documentElement.scrollHeight);
  await page.setViewportSize({ width: 1440, height: guideHeight });
  await shot(page, "dashboard-onboarding.png");
  await page.setViewportSize({ width: 1440, height: 900 });

  // Dark theme.
  await page.goto(agentUrl);
  await page.getByRole("button", { name: "Switch to dark theme" }).click();
  await expect(page.locator(".history-svg")).toBeVisible();
  await shot(page, "dashboard-agent-dark.png");
  await page.getByRole("button", { name: "Switch to light theme" }).click();

  // Phone width.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(agentUrl);
  await expect(page.getByTestId("decision-banner")).toBeVisible();
  await expect(page.locator(".history-svg")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow, "horizontal overflow at 390px").toBeLessThanOrEqual(0);
  await shot(page, "dashboard-agent-mobile.png");

  expectClean(problems);
  await context.close();
});
