import { test, expect, devices, type Page } from '@playwright/test';
import { seedAliceWithBob, depositNote } from './fixtures/deposit-note';

/**
 * NEG: an unbroken 300-char body (fingerprint-shaped) must wrap inside the bubble.
 * scrollWidth of the bubble ≤ viewport; the page itself must not grow a horizontal scrollbar.
 */

async function genesisReceiver(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

const { defaultBrowserType: _ignoredBrowserType, ...pixel7Mobile } = devices['Pixel 7'];

const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7)', use: pixel7Mobile },
];

const UNBROKEN = 'ab'.repeat(150); // 300 chars, no spaces — a fingerprint-length wall

for (const variant of MATRIX) {
  test.describe(`notes bubble wrap · ${variant.label}`, () => {
    test.use(variant.use);

    test('NEG: a 300-char unbroken string does not overflow the viewport', async ({ page, request }) => {
      test.setTimeout(90_000);

      await genesisReceiver(page, 'Alice Wrap');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);

      const { note_id, thread_id, status } = await depositNote(request, {
        sender: bob,
        recipientFingerprint: aliceFp,
        recipientPublicKeyArmored: aliceArmoredPub,
        fields: { body: UNBROKEN },
      });
      expect(status).toBe(200);

      const notesTab = page.getByTestId('tab-notes');
      await expect(notesTab).toBeVisible({ timeout: 20_000 });
      await notesTab.click();
      await expect(page.getByTestId('notes-inbox')).toBeVisible();

      const threadBtn = page.getByTestId(`notes-thread-${thread_id}`);
      await expect(threadBtn).toBeVisible({ timeout: 25_000 });
      await threadBtn.click();

      const bubble = page.getByTestId(`notes-bubble-${note_id}`);
      await expect(bubble).toBeVisible({ timeout: 10_000 });
      await expect(bubble).toContainText(UNBROKEN);

      const viewport = page.viewportSize();
      expect(viewport).toBeTruthy();
      const metrics = await bubble.evaluate((el) => {
        const root = document.documentElement;
        return {
          bubbleScrollWidth: el.scrollWidth,
          pageScrollWidth: root.scrollWidth,
          innerWidth: window.innerWidth,
        };
      });
      expect(metrics.bubbleScrollWidth, 'bubble must not be wider than the viewport').toBeLessThanOrEqual(
        viewport!.width,
      );
      expect(metrics.pageScrollWidth, 'page must not grow a horizontal scrollbar').toBeLessThanOrEqual(
        metrics.innerWidth + 1,
      );
    });
  });
}
