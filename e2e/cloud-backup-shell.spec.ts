import { test, expect } from '@playwright/test';

// Cloud-backup UI shell: connect a target, read status, trigger backup / restore.
// Transport is not live — connect is a device-local target; backup opens existing
// Full Backup dialog; restore on the start screen still uses the file picker.

async function createIdentity(page: import('@playwright/test').Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Alice E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

test('connect a cloud backup target, see status, trigger backup', async ({ page }) => {
  test.setTimeout(60_000);
  await createIdentity(page);
  await page.getByRole('tab', { name: 'Identity' }).click();

  const shell = page.getByTestId('cloud-backup-shell');
  await expect(shell).toBeVisible();
  await expect(page.getByTestId('cloud-backup-status')).toHaveText(/No backup on this device yet/i);

  await page.getByTestId('cloud-backup-target-dropbox').click();
  await expect(page.getByTestId('cloud-backup-connected')).toHaveText(/Dropbox/);
  await expect(page.getByTestId('cloud-backup-transport-pending')).toBeVisible();
  await expect(page.getByTestId('cloud-backup-transport-pending')).not.toHaveText(/seamless/i);
  await expect(page.getByTestId('cloud-backup-transport-pending')).not.toHaveText(/end-to-end/i);

  await page.getByTestId('cloud-backup-now').click();
  await expect(page.getByTestId('export-auth-gate')).toBeVisible();
});

test('restore-from-backup on the start screen triggers the file picker', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await expect(page.getByTestId('cloud-backup-shell')).toBeVisible();

  await page.getByTestId('cloud-backup-target-icloud').click();
  await expect(page.getByTestId('cloud-backup-connected')).toHaveText(/iCloud/);

  const [chooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.getByTestId('cloud-backup-restore').click(),
  ]);
  expect(chooser).toBeTruthy();
});
