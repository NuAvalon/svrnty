import { defineConfig, devices } from '@playwright/test';

// Deployed Node Zero G-D verify — runs against the PROD server (`next start` over the built app + the REAL
// bundled public/sw.js + the signed release.json), NOT `npm run dev`: the SW verifies served assets against the
// prod-signed manifest, which only matches a real production build. This is the "deployed, not just module KATs"
// harness (Archie #142294 / #142312).
//
// PREREQ: `npm run build` (runs build:sw → real public/sw.js) THEN `npx tsx scripts/sign-release.ts` (writes the
// signed public/.well-known/svrnty/release.json). RUN: npx playwright test --config playwright.sw.config.ts
const PORT = 3212;
export default defineConfig({
  testDir: './e2e',
  testMatch: /nodezero-sw\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  retries: 1,
  timeout: 90_000,
  expect: { timeout: 20_000 },
  reporter: 'list',
  use: { baseURL: `http://localhost:${PORT}`, headless: true, trace: 'on-first-retry' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npx next start -p ${PORT}`,
    url: `http://localhost:${PORT}`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
