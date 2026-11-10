import { test, expect, type Page } from '@playwright/test';

async function genesis(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Relay Owner');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

test.use({ serviceWorkers: 'block' });

test('Settings → Relay says where you are and what a relay sees, and offers no way to switch', async ({ page, baseURL }) => {
  test.setTimeout(90_000);
  const foreign: string[] = [];
  const home = new URL(baseURL!).origin;
  page.on('request', (r) => {
    const u = new URL(r.url());
    if ((u.protocol === 'http:' || u.protocol === 'https:') && u.origin !== home) foreign.push(r.url());
  });

  await genesis(page);
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  const panel = page.getByTestId('relay-settings');
  await expect(panel).toBeVisible();
  await panel.scrollIntoViewIfNeeded();
  await expect(panel.getByTestId('relay-current')).toContainText("You're on:");
  await expect(panel.getByTestId('relay-helper')).toContainText('never what your messages say');
  await expect(panel.getByTestId('relay-helper')).toContainText('your identity key');
  await expect(panel.getByTestId('relay-unavailable')).toHaveText("Moving to another relay isn't available in the app yet.");

  await expect(panel.getByRole('textbox')).toHaveCount(0);
  await expect(panel.getByRole('button')).toHaveCount(0);
  await expect(page.getByTestId('relay-url-input')).toHaveCount(0);
  await expect(page.getByTestId('relay-switch')).toHaveCount(0);
  expect(foreign).toEqual([]);
});
