import { test, expect } from '@playwright/test';

// P0 life-safety: sender Distress is Coming — disabled, not a cry for help.
async function genesis(page: import('@playwright/test').Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Distress E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

test('Distress control is disabled Coming — copy says it is not live', async ({ page }) => {
  test.setTimeout(60_000);
  await genesis(page);

  await page.getByRole('button', { name: /^recovery$/i }).click();
  const sheet = page.getByRole('dialog', { name: 'Recovery' });
  await expect(sheet).toBeVisible();

  const menu = sheet.getByTestId('distress-coming-menu');
  await expect(menu).toHaveText(/Distress — coming/i);
  await menu.click();

  await expect(sheet.getByRole('heading', { name: /Distress signal — coming/i })).toBeVisible();
  await expect(sheet).toContainText(/isn['’]t live yet/i);
  await expect(sheet).toContainText(/would do nothing/i);

  const control = sheet.getByTestId('distress-coming-control');
  await expect(control).toHaveText(/^Coming$/);
  await expect(control).toBeDisabled();

  await expect(sheet).not.toContainText(/emergency/i);
  await expect(sheet).not.toContainText(/auto-?dial/i);
  await expect(sheet).not.toContainText(/calling for help/i);
});
