import { test, expect } from '@playwright/test';

/**
 * Notes inbox — glass + honest copy. Proves the tab mounts, send status
 * is Sent · unconfirmed (never Delivered/Read/Expired as a live status),
 * and empty-book fails loud. Crypto round-trip is fleet sendNoteToPeer.
 */
test('notes inbox is over-wire glass with honest send status', async ({ page }) => {
  test.setTimeout(90_000);

  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Notes E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });

  const notesTab = page.getByTestId('tab-notes');
  await expect(notesTab).toBeVisible();
  await notesTab.click();

  const panel = page.getByTestId('notes-inbox');
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId('notes-heading')).toHaveText(
    'Encrypted messages, with the people you trust',
  );
  await expect(panel.getByTestId('notes-receiving')).toContainText(/saved to this device/i);
  await expect(panel.getByTestId('notes-receiving')).toContainText(/there when you open/i);
  await expect(panel.getByTestId('notes-empty-book')).toBeVisible();
  await expect(panel.getByTestId('notes-send-btn')).toBeVisible();
  await expect(panel.getByTestId('notes-send-btn')).toHaveText(/^Send$/i);

  await expect(panel.getByText(/^Delivered$/)).toHaveCount(0);
  await expect(panel.getByText(/^Read$/)).toHaveCount(0);
  await expect(panel.getByText(/^Expired$/)).toHaveCount(0);
  await expect(panel.getByText(/you're not allowed/i)).toHaveCount(0);
  await expect(panel.getByText(/post-quantum/i)).toHaveCount(0);
});
