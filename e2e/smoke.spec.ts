import { test, expect } from '@playwright/test';

// Smoke: the app boots against `next dev` and renders the identity gate. This proves the harness
// reaches the running app end-to-end — the foundation the import / ceremony demo-arc specs build on.
// (If this fails, the whole e2e suite is meaningless — so it runs first and stays deliberately robust.)
test('landing is Continue-only; Grow mints', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: /svrnty/i }).first()).toBeVisible();
  await expect(page.getByText('SVRNTY.IS YOURS')).toBeVisible();
  await expect(page.getByTestId('gate-continue')).toBeVisible();
  await expect(page.getByTestId('nav-grow')).toBeVisible();
  await expect(page.getByRole('button', { name: /^start$/i })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /generate a new cryptographic identity/i })).toHaveCount(0);
});
