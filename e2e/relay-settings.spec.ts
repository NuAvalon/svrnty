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

test('Settings → Relay validates and never auto-switches', async ({ page }) => {
  test.setTimeout(90_000);
  await page.route('**/*', async (route) => {
    const url = route.request().url();
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*' };
    if (route.request().method() === 'OPTIONS' && url.includes('/health')) {
      await route.fulfill({ status: 204, headers: cors });
      return;
    }
    if (url.startsWith('https://reg.example:8101/health')) {
      await route.fulfill({
        status: 200,
        headers: { ...cors, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'online', service: 'registration' }),
      });
      return;
    }
    if (url.startsWith('https://your-relay.example:8100/health')) {
      await route.fulfill({
        status: 200,
        headers: { ...cors, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'online', service: 'satellite', mode: 'full' }),
      });
      return;
    }
    await route.continue();
  });

  await genesis(page);
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  const panel = page.getByTestId('relay-settings');
  await expect(panel).toBeVisible();
  await panel.scrollIntoViewIfNeeded();
  await expect(panel.getByTestId('relay-current')).toContainText("You're on:");
  await expect(panel.getByTestId('relay-helper')).toContainText(
    'never your notes (those stay sealed end-to-end)',
  );
  await expect(panel.getByTestId('relay-switch')).toBeDisabled();

  await panel.getByTestId('relay-url-input').fill('https://reg.example:8101');
  await expect(panel.getByTestId('relay-health')).toContainText('registration-only — need a full relay');
  await expect(panel.getByTestId('relay-switch')).toBeDisabled();

  await panel.getByTestId('relay-url-input').fill('https://your-relay.example:8100');
  await expect(panel.getByTestId('relay-health')).toContainText('valid');
  await expect(panel.getByTestId('relay-switch')).toBeEnabled();

  await panel.getByTestId('relay-switch').click();
  await expect(page.getByTestId('relay-confirm')).toBeVisible();
  await page.getByTestId('relay-confirm-go').click();
  await expect(page.getByTestId('relay-result')).toBeVisible();
  await expect(page.getByTestId('relay-result')).not.toContainText(/You're now on/i);
  await expect(page.getByTestId('relay-result')).not.toContainText(/^done$/i);
  await expect(page.getByTestId('relay-current')).not.toContainText('your-relay.example');
  await page.screenshot({
    path: '/opt/cursor/artifacts/screenshots/relay-settings-valid.png',
    fullPage: true,
  });
});
