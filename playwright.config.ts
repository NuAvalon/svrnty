import { defineConfig, devices } from '@playwright/test';

// Playwright e2e against the dev server. The demo-critical flows (contact import, the trust
// ceremony) render React that can't be verified in-container any other way — this is the
// standing verification path (T11 demo-arc). `webServer` boots `next dev` and
// tears it down automatically; CI installs the browser, then runs `playwright test`.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    headless: true,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // RELAY_RATE_LIMIT_MAX: every e2e deposit comes from ONE client IP, so the notes specs and
    // return-channel's setup share one 10-per-60 s bucket and overflow it when timing lines up (#630
    // condition 3). Raised here only, by env; production keeps 10, pinned by mailbox-rate-limit.test.ts.
    command: 'RELAY_DB_PATH=/tmp/svrnty-e2e-relay/mailbox.sqlite RELAY_RATE_LIMIT_MAX=1000 npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
