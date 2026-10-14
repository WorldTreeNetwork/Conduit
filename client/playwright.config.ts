import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.CONDUIT_CLIENT_PORT ?? 5179);

/**
 * E2E runs the real conduit-server binary against a fresh PostgreSQL
 * database (see e2e/global-setup.ts) and the client from the Vite dev
 * server, pointed at the ephemeral homeserver with ?hs=.
 */
export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: true,
  workers: process.env.CI ? 2 : 3,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `pnpm exec vite --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    env: { VITE_CONDUIT_TEST_HOOKS: "1" },
  },
});
