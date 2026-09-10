import { test, expect } from '@playwright/test';
import { genesis } from './helpers/genesis';

// GROW 2-tab: Join collapsed into Grow as "Show my code" | "Scan / paste".
// Consent: paste/scan still only MOUNTS JoinerCeremony — no auto-connect.

test.describe('Grow 2-tab — Join merged into Grow', () => {
  test('desktop: one Grow entry; default Show my code; Scan / paste hosts join; ceremony escapes tabs', async ({
    page,
  }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Grow Tabs');

    await expect(page.getByTestId('nav-grow')).toBeVisible();
    await expect(page.getByTestId('nav-join')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^Join$/ })).toHaveCount(0);

    await page.getByTestId('nav-grow').click();
    const dialog = page.getByTestId('grow-surface');
    await expect(dialog).toBeVisible();

    await expect(dialog.getByRole('tab', { name: 'Show my code' })).toHaveAttribute(
      'data-state',
      'active',
    );
    await expect(dialog.getByRole('heading', { name: /show them your card/i })).toBeVisible();
    await expect(
      dialog.getByLabel(/number of people who can join with this link/i),
    ).toBeVisible();

    await dialog.getByRole('tab', { name: 'Scan / paste' }).click();
    await expect(dialog.getByTestId('scan-invite-button')).toBeVisible();
    await expect(dialog.getByLabel(/paste your invite link/i)).toBeVisible();

    await dialog.getByLabel(/paste your invite link/i).fill(
      'https://svrnty.is/c/e2egrow#e2ekeyfrag',
    );
    await dialog.getByRole('button', { name: /^join$/i }).click();

    const overlay = page.getByTestId('joiner-ceremony-overlay');
    await expect(overlay).toBeVisible();
    await expect(page.getByText(/opening the secure channel/i)).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('body')).not.toContainText('e2ekeyfrag');
    await expect(overlay).toHaveCSS('position', 'fixed');
  });
});
