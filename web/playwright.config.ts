import { defineConfig, devices } from "@playwright/test";

// End-to-end tests against a real daemon with the web UI built in.
// Build it first (from the repository root): make daemon
// Then: cd web && pnpm test:e2e
export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  globalTeardown: "./e2e/global-teardown.ts",
  // One daemon, one worker: some journeys (emergency stop) affect every
  // session, so tests run one after another.
  workers: 1,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 8_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.CONDUIT_E2E_URL,
    trace: "retain-on-failure",
    // The build container routes traffic through a proxy; the daemon is local.
    launchOptions: { args: ["--no-proxy-server"] },
  },
  projects: [
    { name: "first-run", testMatch: /first-run\.setup\.ts/, use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 900 } } },
    {
      name: "desktop",
      dependencies: ["first-run"],
      testIgnore: /first-run\.setup\.ts/,
      use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 900 } },
    },
    {
      name: "phone",
      dependencies: ["first-run"],
      testIgnore: /first-run\.setup\.ts|a11y\.spec\.ts/,
      use: { ...devices["Desktop Chrome"], viewport: { width: 412, height: 900 }, isMobile: false, hasTouch: true },
    },
  ],
});
