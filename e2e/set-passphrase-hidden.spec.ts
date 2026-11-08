import { test, expect } from '@playwright/test';

// "Set Passphrase" is switched off until the re-key fix ships. Changing the passphrase of an identity that is already encrypted at rest re-stores only its
// keys, so its contacts, recovery vault and shards stop opening and the owner is told nothing. This drives the real screen: the identity card's menu opens
// and offers its other actions, and "Set Passphrase" is not among them.
const UNLOCK_PW = 'unlock-e2e-pass-1234';

test('the identity card menu does not offer Set Passphrase', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('No Set Passphrase E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 45_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });

  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  // The menu really is open: its neighbouring actions are there (matched as menu items; some of these words also appear elsewhere on the page).
  await expect(page.getByRole('menuitem', { name: 'Export Contacts' })).toBeVisible();
  await expect(page.getByRole('menuitem', { name: 'Lenses & vault' })).toBeVisible();
  // And no passphrase item is: not as a menu item, and not as text anywhere on the page.
  await expect(page.getByRole('menuitem', { name: /passphrase/i })).toHaveCount(0);
  await expect(page.getByText('Set Passphrase', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Passphrase set', { exact: true })).toHaveCount(0);
});
