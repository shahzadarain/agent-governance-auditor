// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "@playwright/test";

// The end-to-end tests drive the built bundle as the Go server serves it, so
// the real Content-Security-Policy is in force. They use an installed Chrome
// (or Edge with PW_CHANNEL=msedge) and do not download a browser.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  outputDir: "test-results",
  use: {
    baseURL: process.env.AGENTGOV_URL ?? "http://127.0.0.1:8090",
    channel: process.env.PW_CHANNEL ?? "chrome",
    headless: true,
    viewport: { width: 1440, height: 900 },
    colorScheme: "light",
    trace: "retain-on-failure",
  },
});
