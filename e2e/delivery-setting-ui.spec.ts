import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

/**
 * R2b: the Delivery setting, in the real app. Settings (Identity tab): the one-time upgrade notice, the global On/Off, the one-time ask after a
 * restore; the contact card: the per-contact choice. The send-time rule has its own tests (R2a); these assert what the OWNER sees and can change.
 * The restore ask is reached by planting the documented plaintext "restored here" marker before the panel first reads (the same marker the
 * restore paths that have no session key leave), not by running a full restore: that path is covered by delivery-restore-marks.test.ts.
 */
test.use({ serviceWorkers: 'block' });

const NOTICE =
  'Delivery receipts are on. They let people see that your device received their notes, and roughly when you were online. You can turn them off in Settings.';
const ASK =
  'Should this device let people see that it received their notes, and roughly when you were online? No receipts go out until you choose.';
const GLOBAL_LINE = 'Lets people see that your device received their notes, and roughly when you were online.';
const CONTACT_LINE = 'Lets this person see that your device received their note, and roughly when you were online.';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('delivery-ui@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

async function activeFingerprint(page: Page): Promise<string> {
  const fp = await page.evaluate(
    () =>
      new Promise<string | null>((resolve) => {
        const req = indexedDB.open('svrnty');
        req.onsuccess = () => {
          try {
            const g = req.result.transaction('settings', 'readonly').objectStore('settings').get('active_fingerprint');
            g.onsuccess = () => resolve((g.result && g.result.value) || null);
            g.onerror = () => resolve(null);
          } catch { resolve(null); }
        };
        req.onerror = () => resolve(null);
      }),
  );
  expect(fp, 'active fingerprint persisted after the ceremony').toBeTruthy();
  return fp as string;
}

async function plantRestoredMarker(page: Page, fp: string) {
  await page.evaluate(
    (f) =>
      new Promise<void>((resolve, reject) => {
        const req = indexedDB.open('svrnty');
        req.onsuccess = () => {
          const tx = req.result.transaction('settings', 'readwrite');
          tx.objectStore('settings').put({ key: `delivery_receipts_restored:${f}`, value: '1' });
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        };
        req.onerror = () => reject(req.error);
      }),
    fp,
  );
}

const panel = (page: Page) => page.getByTestId('delivery-settings');
async function openIdentity(page: Page) {
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  await expect(panel(page)).toBeVisible({ timeout: 15_000 });
  await panel(page).scrollIntoViewIfNeeded();
}

const VIEWPORTS: Array<[string, { width: number; height: number } | null]> = [
  ['desktop', null],
  ['phone 390x844', { width: 390, height: 844 }],
];

for (const [vpName, viewport] of VIEWPORTS) {
  test.describe(`Delivery setting UI — ${vpName}`, () => {
    test.setTimeout(150_000);
    if (viewport) test.use({ viewport });

    test('upgrade notice shows once with the exact words, the switch flips and sticks', async ({ page }) => {
      await genesis(page, 'Delivery Owner');
      await openIdentity(page);
      await expect(panel(page)).toHaveAttribute('data-state', 'on');
      await expect(page.getByTestId('delivery-upgrade-notice')).toHaveText(new RegExp(NOTICE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*OK'));
      await expect(page.getByTestId('delivery-line')).toHaveText(GLOBAL_LINE);
      await expect(page.getByTestId('delivery-restore-ask')).toHaveCount(0);

      await page.getByTestId('delivery-notice-dismiss').click();
      await expect(page.getByTestId('delivery-upgrade-notice')).toHaveCount(0);
      await expect(panel(page)).toHaveAttribute('data-state', 'on'); // dismissing is not a choice: the value is kept

      await page.getByTestId('delivery-off').click();
      await expect(panel(page)).toHaveAttribute('data-state', 'off');
      await expect(page.getByTestId('delivery-off')).toHaveAttribute('aria-pressed', 'true');
      await expect(page.getByTestId('delivery-on')).toHaveAttribute('aria-pressed', 'false');

      // read back from the sealed store, not from component state: leave the tab and come back
      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
      await openIdentity(page);
      await expect(panel(page)).toHaveAttribute('data-state', 'off');
      await expect(page.getByTestId('delivery-upgrade-notice')).toHaveCount(0); // once, not every visit
    });

    test('NEG: after a restore the owner is asked once, nothing is chosen for them, and No sticks', async ({ page }) => {
      await genesis(page, 'Delivery Restored');
      const fp = await activeFingerprint(page);
      await plantRestoredMarker(page, fp);
      await openIdentity(page);

      await expect(panel(page)).toHaveAttribute('data-state', 'unknown');
      await expect(page.getByTestId('delivery-restore-ask')).toContainText(ASK);
      await expect(page.getByTestId('delivery-upgrade-notice')).toHaveCount(0);
      await expect(page.getByTestId('delivery-on')).toHaveCount(0); // no switch until the question is answered
      await expect(page.getByTestId('delivery-off')).toHaveCount(0);

      await page.getByTestId('delivery-restore-no').click();
      await expect(panel(page)).toHaveAttribute('data-state', 'off');
      await expect(page.getByTestId('delivery-restore-ask')).toHaveCount(0);

      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
      await openIdentity(page);
      await expect(panel(page)).toHaveAttribute('data-state', 'off'); // asked once
      await expect(page.getByTestId('delivery-restore-ask')).toHaveCount(0);
    });

    test('restore ask: Yes turns it on', async ({ page }) => {
      await genesis(page, 'Delivery Yes');
      await plantRestoredMarker(page, await activeFingerprint(page));
      await openIdentity(page);
      await expect(panel(page)).toHaveAttribute('data-state', 'unknown');
      await page.getByTestId('delivery-restore-yes').click();
      await expect(panel(page)).toHaveAttribute('data-state', 'on');
      await expect(page.getByTestId('delivery-upgrade-notice')).toHaveCount(0);
    });

    test('per-contact choice: three states, stored, and the card menu opens it', async ({ page }) => {
      await genesis(page, 'Delivery Contact');
      await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
      await seedSampleGalaxy(page);
      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
      const row = page
        .locator('[data-testid="contact-row"]')
        .filter({ hasText: 'Hypatia' })
        .filter({ hasNotText: 'Alexandria' })
        .first();
      await expect(row).toBeVisible({ timeout: 25_000 });
      await row.click();

      const open = async () => {
        const card = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
        await expect(card).toBeVisible();
        const toggle = card.getByTestId('card-actions-toggle');
        await toggle.scrollIntoViewIfNeeded();
        await toggle.click({ timeout: 10_000 });
        await card.getByTestId('contact-delivery-open').click();
        await expect(page.getByTestId('contact-delivery-dialog')).toBeVisible();
      };

      await open();
      await expect(page.getByTestId('contact-delivery-line')).toHaveText(CONTACT_LINE);
      await expect(page.getByTestId('contact-delivery-follow')).toHaveAttribute('aria-pressed', 'true'); // default: follow my setting
      await page.getByTestId('contact-delivery-off').click();
      await expect(page.getByTestId('contact-delivery-off')).toHaveAttribute('aria-pressed', 'true', { timeout: 10_000 });
      await expect(page.getByTestId('contact-delivery-error')).toHaveCount(0);
      await page.keyboard.press('Escape');
      await expect(page.getByTestId('contact-delivery-dialog')).toHaveCount(0);

      // reopen: the choice comes back from the store
      await open();
      await expect(page.getByTestId('contact-delivery-off')).toHaveAttribute('aria-pressed', 'true');
      await page.getByTestId('contact-delivery-on').click();
      await expect(page.getByTestId('contact-delivery-on')).toHaveAttribute('aria-pressed', 'true', { timeout: 10_000 });
      await page.getByTestId('contact-delivery-follow').click();
      await expect(page.getByTestId('contact-delivery-follow')).toHaveAttribute('aria-pressed', 'true', { timeout: 10_000 });
    });
  });
}
