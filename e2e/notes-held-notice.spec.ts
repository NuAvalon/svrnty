import { test, expect, devices, type Page } from '@playwright/test';
import { seedAliceWithBob, depositRawBlob } from './fixtures/deposit-note';

/**
 * #720 "flag, don't hide": a hybrid message this device cannot open YET is KEPT on the relay and the Chat tab SAYS SO.
 *
 * The scenario is Peter's: a device that advertises an ML-KEM public key but does not hold the matching secret (keys not restored here).
 * The fixture reproduces exactly that in a real browser: genesis (keys present), then delete this identity's `pq_keys` record from the
 * client-store IndexedDB. No test hook exists in production code.
 *
 *   CONTROL  keys present   -> the same hybrid-shaped blob is a plain terminal drop (acked): NO notice, ever.
 *   HELD     keys removed   -> the blob stays on the relay: the notice appears, and it is still there several polls later.
 *            "Still there" is the proof that nothing acked it: an acked blob would make the next clean poll report 0 and clear the notice.
 *
 * The blob is hybrid-SHAPED only (the loud gate is a shape check; nothing is opened before it), so no real ciphertext is needed.
 */

const HYBRID_SHAPED = JSON.stringify({
  v: 1,
  alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM',
  mailbox_fp: 'ab'.repeat(32),
  epk: 'e',
  kem_ct: 'k',
  nonce: 'n',
  ct: 'c',
});

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

async function openChat(page: Page) {
  const tab = page.getByTestId('tab-notes');
  await expect(tab).toBeVisible({ timeout: 20_000 });
  await tab.click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
}

/** Remove this identity's ML-KEM secret record, as if the keys were never restored on this device. Returns whether a record existed. */
async function removePqKeys(page: Page, fp: string): Promise<boolean> {
  return page.evaluate(
    (f) =>
      new Promise<boolean>((resolve, reject) => {
        const open = indexedDB.open('svrnty');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const db = open.result;
          const tx = db.transaction('pq_keys', 'readwrite');
          const store = tx.objectStore('pq_keys');
          const get = store.get(f);
          get.onsuccess = () => {
            const existed = get.result !== undefined;
            store.delete(f);
            tx.oncomplete = () => {
              db.close();
              resolve(existed);
            };
          };
          tx.onerror = () => reject(tx.error);
        };
      }),
    fp,
  );
}

const { defaultBrowserType: _ignoredBrowserType, ...pixel7Mobile } = devices['Pixel 7'];
const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7)', use: pixel7Mobile },
];

for (const variant of MATRIX) {
  test.describe(`held notice · ${variant.label}`, () => {
    test.use(variant.use);

    test('CONTROL: with the keys present the same hybrid-shaped blob is a plain drop and no notice ever shows', async ({ page, request }) => {
      test.setTimeout(90_000);
      await genesisReceiver(page, 'Alice Control');
      const { aliceFp } = await seedAliceWithBob(page);
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: HYBRID_SHAPED })).toBe(200);
      await openChat(page);
      await page.waitForTimeout(8_000); // several poll cycles
      await expect(page.getByTestId('notes-held-notice')).toHaveCount(0);
    });

    test('HELD: with the ML-KEM secret removed the blob is kept and the Chat tab says so, and keeps saying so after later polls', async ({ page, request }) => {
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Alice Held');
      const { aliceFp } = await seedAliceWithBob(page);
      expect(await removePqKeys(page, aliceFp), 'the identity had a pq_keys record to remove').toBe(true);
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: HYBRID_SHAPED })).toBe(200);
      await openChat(page);

      const notice = page.getByTestId('notes-held-notice');
      await expect(notice).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId('notes-held-text')).toContainText("1 message couldn't be opened on this device: it was sealed to a key this device doesn't have.");
      // The relay (dev, after #306) reports expires_at, so the line names the moment it will delete the message: local date AND time,
      // with the year (copy v0.4/v0.5). Never the no-date fallback here, and never a date computed on the device.
      await expect(page.getByTestId('notes-held-text')).toContainText(/It's kept on the relay until [A-Z][a-z]{2} \d{1,2}, \d{4}, \d{1,2}:\d{2}\s?[AP]M, and this app will try again\./);
      // That date is the relay's: about 7 days out for a message deposited just now (the default TTL), not earlier and not absurd.
      const line = (await page.getByTestId('notes-held-text').innerText()).match(/until (.+?), and this app/)?.[1] ?? '';
      const days = (Date.parse(line.replace(/(\d{4}), /, '$1 ')) - Date.now()) / 86_400_000;
      expect(days, `deadline "${line}" should be about 7 days out`).toBeGreaterThan(6.5);
      expect(days).toBeLessThan(7.1);
      await expect(page.getByTestId('notes-held-hint')).toHaveText('Restoring your keys on this device may open it.');
      // Never the words the copy forbids, and no sender or blob text.
      await expect(notice).not.toContainText(/\b(lost|corrupt|spam|forged|fake)\b/i);
      await expect(notice).not.toContainText('ab'.repeat(8));

      // Kept, not acked: several clean polls later the report is still 1 (an acked blob would make the next poll report 0 and clear it).
      await page.waitForTimeout(10_000);
      await expect(notice).toBeVisible();
      await expect(page.getByTestId('notes-held-text')).toContainText('1 message');
    });
  });
}
