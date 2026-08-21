import { defineConfig, devices } from '@playwright/test';

// Prod-build demo-arc config (Athena). beat-3 (guided-Ceremony) is PROD-ONLY: React StrictMode
// double-invoke breaks the joiner mount under `next dev`, so beat-3 can only be verified against a
// production build. This runs the demo-arc against `next start` on a dedicated :3017 (no contact with
// any stray :3000 dev server). Setting E2E_PROD here makes the beat-3 skip-guard
// (test.skip(!process.env.E2E_PROD, …)) run beat-3 whenever this config is used — local or CI e2e-prod.
process.env.E2E_PROD = '1';

export default defineConfig({
  testDir: './e2e',
  testMatch: /demo-arc\.spec\.ts/,
  timeout: 180_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:3017',
    trace: 'off',
    video: 'off',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'PORT=3017 npm run start',
    url: 'http://localhost:3017',
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
