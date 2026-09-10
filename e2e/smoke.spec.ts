import { test, expect } from '@playwright/test';
import { openGrow } from './helpers/genesis';

// Smoke: the app boots against `next dev` and renders the identity gate. This proves the harness
// reaches the running app end-to-end — the foundation the import / ceremony demo-arc specs build on.
// (If this fails, the whole e2e suite is meaningless — so it runs first and stays deliberately robust.)
test('landing is Continue-only; Grow is join-only; genesis is not Grow', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: /svrnty/i }).first()).toBeVisible();
  await expect(page.getByText('SVRNTY.IS YOURS')).toBeVisible();
  await expect(page.getByTestId('gate-continue')).toBeVisible();
  await expect(page.getByTestId('nav-grow')).toBeVisible();
  await expect(page.getByTestId('lattice-genesis')).toBeVisible();
  await expect(page.getByRole('button', { name: /^start$/i })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /generate a new cryptographic identity/i })).toHaveCount(0);

  await openGrow(page);
  const surface = page.getByTestId('grow-surface');
  await expect(surface).toBeVisible();
  await expect(surface.getByTestId('grow-join-only')).toBeVisible();
  await expect(surface.getByLabel(/paste your invite link/i)).toBeVisible();
  await expect(surface.getByTestId('scan-invite-button')).toBeVisible();
  await expect(page.getByTestId('grow-forge-submit')).toHaveCount(0);
  await expect(page.getByPlaceholder('Your name')).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'Show my code' })).toHaveCount(0);
});

test('lattice-genesis opens the first-card form, not Grow', async ({ page }) => {
  await page.goto('/');
  await page.getByTestId('lattice-genesis').click();
  await expect(page.getByTestId('lattice-genesis-submit')).toBeVisible();
  await expect(page.getByPlaceholder('Your name')).toBeVisible();
  await expect(page.getByTestId('grow-forge-submit')).toHaveCount(0);
});
