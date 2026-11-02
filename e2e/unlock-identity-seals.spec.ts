import { test, expect, type Page } from '@playwright/test';

async function genesis(page: Page, name: string) {
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

test('unlock switcher shows a seal next to each other identity', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await genesis(page, 'Seal Alice');
  await page.getByTestId('lock-now-btn').click();
  await expect(page.getByRole('heading', { name: /welcome back/i })).toBeVisible();
  await expect(page.getByTestId('unlock-identity-seal')).toBeVisible();

  await page.getByTestId('new-identity-btn').click();
  await genesis(page, 'Seal Bob');
  await page.getByTestId('lock-now-btn').click();
  await expect(page.getByText('Seal Bob')).toBeVisible();

  const option = page.getByTestId('switch-identity-option').filter({ hasText: 'Seal Alice' });
  await expect(option).toBeVisible();
  const optionSeal = option.getByTestId('switch-identity-seal');
  await expect(optionSeal).toBeVisible();
  await expect(optionSeal).toHaveAttribute('data-fingerprint', /[0-9a-f]{16,}/i);
  await expect(optionSeal.locator('svg[role="img"]')).toBeVisible();

  const bobFp = await page.getByTestId('unlock-identity-seal').getAttribute('data-fingerprint');
  const aliceFp = await optionSeal.getAttribute('data-fingerprint');
  expect(aliceFp).toBeTruthy();
  expect(aliceFp).not.toBe(bobFp);

  await option.click();
  await expect(page.getByTestId('unlock-identity-seal')).toHaveAttribute(
    'data-fingerprint',
    aliceFp || '',
  );
  await expect(page.getByText('Seal Alice', { exact: true }).first()).toBeVisible();
});
