import { defineConfig, devices } from '@playwright/test';

// Playwright e2e against the dev server. The demo-critical flows (contact import, the trust
// ceremony) render React that can't be verified in-container any other way — this is the
// standing verification path Peter asked for (T11 demo-arc). `webServer` boots `next dev` and
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
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
