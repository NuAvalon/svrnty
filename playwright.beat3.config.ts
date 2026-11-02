import { defineConfig, devices } from '@playwright/test';

// Prod-build demo-arc config. beat-3 (guided-Ceremony) is PROD-ONLY: React StrictMode
// double-invoke breaks the joiner mount under `next dev`, so beat-3 can only be verified against a
// production build. This runs the demo-arc against `next start` on a dedicated :3017 (no contact with
// any stray :3000 dev server). Setting E2E_PROD here makes the beat-3 skip-guard
// (test.skip(!process.env.E2E_PROD, …)) run beat-3 whenever this config is used — local or CI e2e-prod.
process.env.E2E_PROD = '1';

export default defineConfig({
  testDir: './e2e',
  testMatch: /demo-arc\.spec\.ts/,
  // beat-3 is a HEAVY 2-device prod ceremony — genesis×2 (OpenPGP + ML-DSA-87 + ML-KEM-1024 keygen)
  // + grow + join + add-to-gate + 2× Argon2id(64MiB) unlocks, across 2 prod contexts. That real
  // crypto cost sits right at the old 180s cap: the failure slid between the Galaxy-tab click (line
  // 115) and the galaxy-gate (124) across runs — timing VARIANCE at the edge ("Test ended" at a
  // shifting line), i.e. the whole test exhausting its budget, NOT a specific click-flake and NOT the
  // galaxy render (never reached). 300s gives the crypto ceremony headroom under CI load.
  // ★ TRIPWIRE: if beat-3 STILL times out at 300s, that is a REAL slowdown to investigate — do NOT
  // keep bumping (a runaway timeout masks a perf regression).
  timeout: 300_000,
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
    command: 'RELAY_DB_PATH=/tmp/svrnty-e2e-relay/mailbox.sqlite PORT=3017 npm run start',
    url: 'http://localhost:3017',
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
