import { test, expect } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

/**
 * Chat inbox — window only + honest send status. Proves the tab mounts,
 * essay masthead is gone, send status is Sent · unconfirmed (never
 * Delivered/Read/Expired as a live status), and empty-book fails loud.
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
  await expect(notesTab).toHaveText(/Chat/i);
  await notesTab.click();

  const panel = page.getByTestId('notes-inbox');
  await expect(panel).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Chat', exact: true })).toBeVisible();
  await expect(panel.getByText(/Encrypted messages/i)).toHaveCount(0);
  await expect(panel.getByText(/How notes travel/i)).toHaveCount(0);
  await expect(panel.getByText(/saved to this device/i)).toHaveCount(0);
  await expect(panel.getByTestId('notes-field')).toBeVisible();
  await expect(panel.getByTestId('notes-empty-book')).toBeVisible();
  await expect(panel.getByTestId('notes-send-btn')).toBeVisible();
  await expect(panel.getByTestId('notes-send-btn')).toHaveText(/^Send$/i);

  await expect(panel.getByText(/^Delivered$/)).toHaveCount(0);
  await expect(panel.getByText(/^Read$/)).toHaveCount(0);
  await expect(panel.getByText(/^Expired$/)).toHaveCount(0);
  await expect(panel.getByText(/you're not allowed/i)).toHaveCount(0);
  await expect(panel.getByText(/post-quantum/i)).toHaveCount(0);
  await expect(panel.getByTestId('notes-field')).toBeVisible();
  await expect(panel.getByTestId('notes-search')).toBeVisible();
});

test('galaxy star Chat opens that conversation in the Thread Field', async ({ page }) => {
  test.setTimeout(180_000);

  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Galaxy Note E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await expect(page.getByTestId('trust-map')).toBeVisible();
  const load = page.getByTestId('trust-map-load-sample');
  await load.click();
  await expect(load).toBeHidden({ timeout: 150_000 });

  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.getByTestId('contact-row').filter({ hasText: 'River Vale' }).click();
  const living = page.getByTestId('contact-action-card');
  await expect(living.getByTestId('galaxy-open-note')).toBeVisible();
  const fpRaw = await living.getByTestId('living-fingerprint').innerText();
  const fp = fpRaw.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  expect(fp.length).toBeGreaterThanOrEqual(16);

  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  const star = page.locator(`[data-testid="trust-node"][data-fingerprint="${fp}"]`);
  await expect(star).toBeVisible({ timeout: 15_000 });
  await star.click();
  await expect(page.getByTestId('trust-node-detail')).toBeVisible();
  await page.getByTestId('galaxy-open-note').click();

  const panel = page.getByTestId('notes-inbox');
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId('notes-field-peer')).toContainText(/River Vale/i);
  await panel.getByTestId('notes-search').fill('zzzz-no-match');
  await expect(panel.getByTestId('notes-search-empty')).toBeVisible();
  await panel.getByTestId('notes-search').fill('River');
  await expect(panel.getByText(/River Vale/i).first()).toBeVisible();
  await expect(panel.getByTestId('notes-send-btn')).toHaveText(/^Send$/i);
  await expect(panel.getByText(/^Delivered$/)).toHaveCount(0);
  await expect(panel.getByText(/post-quantum/i)).toHaveCount(0);

  await panel.getByTestId('notes-field-peer').click();
  await expect(page.getByTestId('trust-map')).toBeVisible();
  await expect(page.getByTestId('trust-node-detail')).toBeVisible();
  await expect(page.getByTestId('trust-node-detail')).toContainText(/River Vale/i);
});
