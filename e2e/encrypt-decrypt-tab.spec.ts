import { test, expect } from '@playwright/test';

/**
 * Encrypt / Decrypt tab — glass only. Proves the tab mounts, copy is honest
 * (Copy ciphertext, never Send; no PQ/E2E claim), and empty-book fails loud.
 * Crypto round-trip is covered by encrypt-decrypt-keys.test.ts against the fleet hooks.
 */
test('encrypt/decrypt tab is no-wire glass with honest copy', async ({ page }) => {
  test.setTimeout(90_000);

  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('EncDec E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });

  const encTab = page.getByTestId('tab-encrypt-decrypt');
  await expect(encTab).toBeVisible();
  await encTab.click();

  const panel = page.getByTestId('encrypt-decrypt-tab');
  await expect(panel).toBeVisible();
  await expect(panel.getByText('Encrypt / Decrypt').first()).toBeVisible();
  await expect(panel.getByText(/this tab does not send anything/i)).toBeVisible();
  await expect(panel.getByTestId('encdec-empty-book')).toBeVisible();
  await expect(panel.getByTestId('encdec-empty-book')).toContainText(
    /classical \(keyless\) contacts cannot be encrypted to/i,
  );

  await expect(panel.getByTestId('encdec-encrypt-btn')).toBeVisible();
  await panel.getByTestId('encdec-mode-decrypt').click();
  await expect(panel.getByTestId('encdec-decrypt-btn')).toBeVisible();

  await expect(panel.getByRole('button', { name: /^send$/i })).toHaveCount(0);
  await expect(panel.getByText(/post-quantum|end-to-end|pq-hybrid/i)).toHaveCount(0);
});
