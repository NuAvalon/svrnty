import { test, expect } from '@playwright/test';

// Smoke: the app boots against `next dev` and renders the identity gate. This proves the harness
// reaches the running app end-to-end — the foundation the import / ceremony demo-arc specs build on.
// (If this fails, the whole e2e suite is meaningless — so it runs first and stays deliberately robust.)
test('landing renders the svrnty identity gate', async ({ page }) => {
  await page.goto('/');
  // The gate title is present on every no-identity landing (app/page.tsx gate + SoverentityFrontend).
  await expect(page.getByRole('heading', { name: /svrnty/i }).first()).toBeVisible();
});
