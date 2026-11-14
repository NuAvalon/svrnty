import { test, expect, type Page } from '@playwright/test';

/**
 * #588 (Flint's SHOULD b): the full-backup export must tell a person, BEFORE the file is saved, when a trust key may be held but cannot be read, because
 * then the backup silently lacks it. It must stay quiet when no trust key exists (nothing is lost), and it must not block the export.
 *
 * Real browser, real screens, the app's own database. "Unreadable" is made the honest way: a row sits where the trust key record lives
 * (settings 'beacon_key:<fingerprint>') but it does not decrypt under this device's session key. A GOOD record cannot be planted from outside (it must be
 * encrypted under the session key, and nothing in the UI creates one while trust is dark), so the "held and readable" case is covered by the pure
 * tests and is NOT run here.
 */
const PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
const NOTICE = /This backup doesn't include your trust key, because it couldn't be read on this device\. Your contacts are included\. If you restore from this backup, the trusts you've made would need to be made again\./;

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PW);
  await page.getByPlaceholder('Confirm passphrase').fill(PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 45_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

async function openExportPassphraseStep(page: Page) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByTestId('vault-export-passphrase')).toBeVisible({ timeout: 30_000 });
}

/** The owner's fingerprint, read from the app's own identities store. */
async function ownerFingerprint(page: Page): Promise<string> {
  return page.evaluate(() => new Promise<string>((resolve, reject) => {
    const r = indexedDB.open('svrnty');
    r.onerror = () => reject(r.error);
    r.onsuccess = () => {
      const db = r.result;
      const q = db.transaction('identities', 'readonly').objectStore('identities').getAllKeys();
      q.onsuccess = () => { db.close(); resolve(String((q.result as IDBValidKey[])[0])); };
      q.onerror = () => reject(q.error);
    };
  }));
}

/** A row where the trust key record lives, shaped like an encrypted payload, that does NOT decrypt under this device's session key. */
async function plantUnreadableRow(page: Page, fp: string) {
  await page.evaluate((fingerprint) => new Promise<void>((resolve, reject) => {
    const r = indexedDB.open('svrnty');
    r.onerror = () => reject(r.error);
    r.onsuccess = () => {
      const db = r.result;
      const tx = db.transaction('settings', 'readwrite');
      tx.objectStore('settings').put({ key: `beacon_key:${fingerprint}`, value: { iv: 'AAAAAAAAAAAAAAAA', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', enc_version: 2 } });
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }), fp);
}

/**
 * Make this a LEGACY identity: its key record is no longer marked encrypted at rest, which is exactly what the app's own hasEncryptedKeys() reads. Such an
 * identity opens with no passphrase and NEVER gets a session key (app/page.tsx), and the export gate accepts it as 'skipped-plaintext'. Returns whether the
 * record lost its marker, so a test can assert its own premise instead of assuming it.
 */
async function makeLegacyUnencrypted(page: Page, fp: string): Promise<boolean> {
  return page.evaluate((fingerprint) => new Promise<boolean>((resolve, reject) => {
    const r = indexedDB.open('svrnty');
    r.onerror = () => reject(r.error);
    r.onsuccess = () => {
      const db = r.result;
      const tx = db.transaction('keys', 'readwrite');
      const store = tx.objectStore('keys');
      const g = store.get(fingerprint);
      g.onsuccess = () => {
        const rec = g.result as Record<string, unknown> | undefined;
        if (!rec || rec.enc_version === undefined) { resolve(false); return; }
        delete rec.enc_version;
        if (store.keyPath) store.put(rec); else store.put(rec, fingerprint);
      };
      tx.oncomplete = () => { db.close(); resolve(true); };
      tx.onerror = () => reject(tx.error);
    };
  }), fp);
}

/** Reload as a legacy identity: the app must open straight to its tabs, with no unlock prompt (no session key is ever set). */
async function reloadAsLegacy(page: Page) {
  await page.reload();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}

test('NONE: an identity with no trust key sees no notice on the export screen (nothing is lost, so nothing is said)', async ({ page }) => {
  test.setTimeout(150_000);
  await genesis(page, 'Notice None');
  await openExportPassphraseStep(page);
  await page.waitForTimeout(2_500); // the look is asynchronous; give it the same time the unreadable case needs
  await expect(page.getByTestId('beacon-key-unreadable-notice')).toHaveCount(0);
});

test('UNREADABLE: a trust key row that cannot be read shows the notice BEFORE the file is saved, in the agreed words, and the export still goes through', async ({ page }, testInfo) => {
  test.setTimeout(240_000);
  await genesis(page, 'Notice Unreadable');
  const fp = await ownerFingerprint(page);
  expect(fp).toMatch(/^[0-9a-f]{64}$/);
  await plantUnreadableRow(page, fp);
  await openExportPassphraseStep(page);
  const notice = page.getByTestId('beacon-key-unreadable-notice');
  await expect(notice).toBeVisible({ timeout: 15_000 });
  await expect(notice).toContainText(NOTICE);
  await page.screenshot({ path: testInfo.outputPath('export-notice.png'), fullPage: true });
  // BEFORE the file is saved: no download has started while the notice is on screen
  // and the export is not blocked by it:
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 120_000 }), page.getByTestId('vault-export-download').click()]);
  expect(download.suggestedFilename()).toMatch(/\.svrnty$/);
});

test('LEGACY NONE: an identity whose keys are not encrypted at rest (no session key all session) and that has NO trust key sees NO notice', async ({ page }) => {
  test.setTimeout(240_000);
  await genesis(page, 'Notice Legacy None');
  const fp = await ownerFingerprint(page);
  expect(await makeLegacyUnencrypted(page, fp), 'premise: the key record lost its encrypted-at-rest marker').toBe(true);
  await reloadAsLegacy(page); // straight to the tabs: the app never asked for a passphrase, so no session key was set
  await openExportPassphraseStep(page);
  await page.waitForTimeout(2_500); // the look is asynchronous; give it the time the unreadable case needs
  // nothing is held, so nothing can be lost, so nothing may be said (before the fix this read 'unreadable' only because the session key was null)
  await expect(page.getByTestId('beacon-key-unreadable-notice')).toHaveCount(0);
});

test('LEGACY ROW: the same identity WITH a trust key row it cannot open still shows the notice (a held key that cannot be read stays loud)', async ({ page }) => {
  test.setTimeout(240_000);
  await genesis(page, 'Notice Legacy Row');
  const fp = await ownerFingerprint(page);
  expect(await makeLegacyUnencrypted(page, fp), 'premise: the key record lost its encrypted-at-rest marker').toBe(true);
  await plantUnreadableRow(page, fp);
  await reloadAsLegacy(page);
  await openExportPassphraseStep(page);
  const notice = page.getByTestId('beacon-key-unreadable-notice');
  await expect(notice).toBeVisible({ timeout: 15_000 });
  await expect(notice).toContainText(NOTICE);
});
