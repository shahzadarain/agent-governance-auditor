// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import path from "node:path";
import { expect, type Page } from "@playwright/test";

export const BASE_URL = process.env.AGENTGOV_URL ?? "http://127.0.0.1:8090";
export const USERNAME = process.env.E2E_USER ?? "admin";
export const PASSWORD = process.env.E2E_PASSWORD ?? "";
export const BOOTSTRAP_TOKEN = process.env.AGENTGOV_BOOTSTRAP_TOKEN ?? "";

const REPO_ROOT = path.resolve(import.meta.dirname, "..", "..");
const BIN = process.env.AGENTGOV_BIN ?? path.join(REPO_ROOT, "bin", process.platform === "win32" ? "agentgov.exe" : "agentgov");

export const VULNERABLE_PROJECT = "Vulnerable example";
export const EXAMPLES_PROJECT = "Reference examples";
export const VULNERABLE_AGENT = "finance-processing-agent";

/** Uploads a real scan of one example folder with the CLI. The token stays in this process. */
export function uploadScan(example: string, token: string, extra: string[] = []): void {
  execFileSync(BIN, ["scan", path.join("examples", example), "--fail-on", "never", "--quiet", "--upload-url", BASE_URL, ...extra], {
    cwd: REPO_ROOT,
    env: { ...process.env, AGENTGOV_TOKEN: token },
    stdio: "pipe",
    timeout: 120_000,
  });
}

export interface Problems {
  consoleErrors: string[];
  cspViolations: string[];
  /**
   * Failed requests that a test expects, as "<status> <path suffix>", for
   * example "401 /api/v1/login" for a wrong password.
   */
  expected: Set<string>;
}

/**
 * Records every console error, page error, and CSP violation of a page.
 *
 * Chrome logs every 4xx answer as a console error. The server has no way to
 * ask "is there a session?" without a 401 answer, so a test that loads the
 * page signed out must list "401 /api/v1/session" first. The same holds for
 * a deliberate wrong password or a deliberate visit to a forbidden object.
 */
export async function watch(page: Page): Promise<Problems> {
  const p: Problems = { consoleErrors: [], cspViolations: [], expected: new Set() };
  page.on("console", (msg) => {
    if (msg.type() !== "error") return;
    const text = msg.text();
    if (/content security policy/i.test(text)) {
      p.cspViolations.push(text);
      return;
    }
    const url = msg.location().url;
    const status = /status of (\d{3})/.exec(text)?.[1];
    if (status) {
      const pathname = new URL(url).pathname;
      for (const e of p.expected) {
        const [code, suffix] = e.split(" ");
        if (code === status && suffix && pathname.endsWith(suffix)) return;
      }
    }
    p.consoleErrors.push(`${text} (${url})`);
  });
  page.on("pageerror", (err) => p.consoleErrors.push(`pageerror: ${err.message}`));
  await page.exposeFunction("__reportCsp", (detail: string) => p.cspViolations.push(detail));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      // @ts-expect-error injected by the test
      void window.__reportCsp(`${e.violatedDirective} blocked ${e.blockedURI}`);
    });
  });
  return p;
}

export function expectClean(p: Problems): void {
  expect(p.cspViolations, "CSP violations").toEqual([]);
  expect(p.consoleErrors, "console errors").toEqual([]);
}

export async function signIn(page: Page, problems: Problems, username = USERNAME, password = PASSWORD): Promise<void> {
  problems.expected.add("401 /api/v1/session");
  await page.goto("/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("user-name")).toHaveText(username);
  problems.expected.delete("401 /api/v1/session");
}

export async function openProject(page: Page, name: string): Promise<void> {
  await page.goto("/projects");
  await page.getByRole("link", { name, exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
}

export async function openAgent(page: Page, project: string, agent: string): Promise<void> {
  await openProject(page, project);
  await page.getByRole("link", { name: agent, exact: true }).click();
  await expect(page.getByTestId("decision-banner")).toBeVisible();
}
