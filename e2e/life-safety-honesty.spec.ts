import { test, expect, type Page } from '@playwright/test';

// Queue #1 — Distress glass is gone. No button, no Coming placeholder, no inbound
// vivre / "I went". Sample data may still carry a fleet-owned inbound flag; the
// map must not paint it.

async function genesis(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Honesty E2E');
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('honesty-e2e@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();

  const welcome = page.getByRole('heading', { name: /welcome back/i });
  try {
    await welcome.waitFor({ state: 'visible', timeout: 3_000 });
    await page.getByPlaceholder('Enter passphrase').fill('e2e-passphrase-1234');
    await page.getByRole('button', { name: /^UNLOCK$/i }).click();
  } catch {
    /* already unlocked */
  }

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 20_000,
  });
}

test('Recovery, Help, and Galaxy carry no distress / panic-send glass', async ({ page }) => {
  test.setTimeout(120_000);
  await genesis(page);

  await page.getByTestId('nav-recovery').click();
  const recovery = page.getByRole('dialog', { name: 'Recovery' });
  await expect(recovery).toBeVisible();
  await expect(recovery).not.toContainText(/distress/i);
  await expect(recovery).not.toContainText(/panic/i);
  await expect(recovery.getByRole('button', { name: /distress/i })).toHaveCount(0);
  await expect(recovery.getByRole('button', { name: /^coming$/i })).toHaveCount(0);
  await recovery.getByRole('button', { name: /back to galaxy/i }).click();
  await expect(recovery).toHaveCount(0);

  await page.getByRole('button', { name: 'Help' }).click();
  const help = page.getByRole('dialog').filter({ hasText: 'The Formula' });
  await expect(help).toBeVisible();
  await expect(help).not.toContainText(/distress/i);
  await help.getByRole('button', { name: /Recovery/ }).click();
  await expect(help).not.toContainText(/distress/i);
  await help.getByRole('button', { name: /got it/i }).click();

  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await expect(page.getByTestId('trust-map')).toBeVisible();
  await page.getByTestId('trust-map-load-sample').click();
  await expect(page.getByTestId('trust-node').first()).toBeVisible({ timeout: 60_000 });

  await expect(page.locator('[data-distress]')).toHaveCount(0);
  await expect(page.getByTestId('vivre-burn')).toHaveCount(0);
  await expect(page.getByTestId('star-ember')).toHaveCount(0);
  await expect(page.getByTestId('vivre-caution')).toHaveCount(0);

  const ada = page.locator('[data-testid="trust-node"]').filter({ hasText: /Ada/ }).first();
  const adaTitle = page.getByTitle(/Ada Lovelace/);
  if ((await adaTitle.count()) > 0) {
    await adaTitle.click({ force: true });
  } else if ((await ada.count()) > 0) {
    await ada.click({ force: true });
  } else {
    await page.getByTestId('trust-node').first().click({ force: true });
  }

  const detail = page.getByTestId('trust-node-detail');
  await expect(detail).toBeVisible();
  await expect(detail).not.toContainText(/distress/i);
  await expect(detail.getByRole('button', { name: /^i went$/i })).toHaveCount(0);
  await expect(page.getByTestId('vivre-burn')).toHaveCount(0);
  await expect(page.getByTestId('vivre-caution')).toHaveCount(0);
});
