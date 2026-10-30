import { test, expect, devices, type Page } from '@playwright/test';
import { DatabaseSync } from 'node:sqlite';
import { seedAliceWithBob, depositRawBlob } from './fixtures/deposit-note';
import { deriveMailboxId } from '../src/lib/relay/mailbox-auth';

/**
 * #720 the ONE ACK DOOR, end to end in a real browser: an envelope that did not become a message gets a metadata-only, ENCRYPTED record in
 * the notes DB BEFORE the relay is told to delete it; an envelope kept for retry is NOT acked.
 *
 *   JUNK      an unopenable blob  -> a dead-letter row appears in the notes DB's `settings` store (encrypted shape, none of the blob's text,
 *             reason unknown-format) AND the relay's mailbox ends up empty (acked) - the row never trails the ack.
 *   HELD      keys removed (Peter's case) + a hybrid-shaped blob -> a `missing-key` row AND the envelope is STILL on the relay.
 *   CONTROL   nothing deposited -> no rows.
 *
 * The relay's sqlite is read-only from here (RELAY_DB_PATH, the same file the dev server writes); the notes DB is read raw from IndexedDB.
 */

const RELAY_DB = process.env.RELAY_DB_PATH ?? '/tmp/svrnty-e2e-relay/mailbox.sqlite';
const JUNK = 'THIS-IS-NOT-A-PGP-MESSAGE-AT-ALL-7f3a';
const HYBRID_SHAPED = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });

function relayCount(aliceFp: string): number {
  const db = new DatabaseSync(RELAY_DB, { readOnly: true });
  try {
    const r = db.prepare('SELECT COUNT(*) AS c FROM envelopes WHERE mailbox_id = ?').get(deriveMailboxId(aliceFp)) as { c: number };
    return r.c;
  } finally {
    db.close();
  }
}

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

/** Raw `settings` rows of this identity's notes DB: what is really on disk. */
async function rawSettings(page: Page, fp: string): Promise<Array<{ key: string; enc?: Record<string, unknown>; value?: unknown }>> {
  return page.evaluate(
    (f) =>
      new Promise<Array<{ key: string; enc?: Record<string, unknown>; value?: unknown }>>((resolve) => {
        const open = indexedDB.open(`svrnty-notes-${f}`);
        open.onerror = () => resolve([]);
        open.onsuccess = () => {
          const db = open.result;
          if (!db.objectStoreNames.contains('settings')) { db.close(); resolve([]); return; }
          const q = db.transaction('settings', 'readonly').objectStore('settings').getAll();
          q.onsuccess = () => { db.close(); resolve(q.result as never); };
          q.onerror = () => { db.close(); resolve([]); };
        };
      }),
    fp,
  );
}
const deadLetters = async (page: Page, fp: string) => (await rawSettings(page, fp)).filter((r) => r.key.startsWith('dead_letter:'));

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
            tx.oncomplete = () => { db.close(); resolve(existed); };
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
  test.describe(`dead-letter door · ${variant.label}`, () => {
    test.use(variant.use);

    test('JUNK: an unopenable blob gets an encrypted metadata-only record, and only then is it acked (relay ends empty)', async ({ page, request }) => {
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Alice Junk');
      const { aliceFp } = await seedAliceWithBob(page);
      expect(await deadLetters(page, aliceFp), 'CONTROL: no records before anything arrives').toHaveLength(0);
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: JUNK })).toBe(200);
      expect(relayCount(aliceFp), 'the blob is on the relay right after the deposit or already consumed; either way never more than 1').toBeLessThanOrEqual(1);

      await expect.poll(async () => (await deadLetters(page, aliceFp)).length, { timeout: 40_000 }).toBe(1);
      const [row] = await deadLetters(page, aliceFp);
      // On disk: {key, enc:{enc_version, iv, ciphertext}} and nothing else - the same shape as a note row; none of the blob's text or the reason in the clear.
      expect(Object.keys(row).sort()).toEqual(['enc', 'key']);
      expect(Object.keys(row.enc ?? {}).sort()).toEqual(['ciphertext', 'enc_version', 'iv']);
      const onDisk = JSON.stringify(row);
      for (const leak of [JUNK, 'unknown-format', 'decrypt-failed', 'other']) expect(onDisk, `"${leak}" must not be readable at rest`).not.toContain(leak);
      expect(row.key).toMatch(/^dead_letter:[A-Za-z0-9._:-]+$/);
      // The plaintext salt row is untouched.
      expect((await rawSettings(page, aliceFp)).filter((r) => r.key === 'notes_encryption_salt')).toHaveLength(1);
      // Acked: the relay's mailbox ends up empty, and stays empty (the row did not trail the ack).
      await expect.poll(() => relayCount(aliceFp), { timeout: 20_000 }).toBe(0);
      await page.waitForTimeout(6_000);
      expect(relayCount(aliceFp)).toBe(0);
      expect(await deadLetters(page, aliceFp), 'one record, not one per poll').toHaveLength(1);
    });

    test('HELD: with the ML-KEM secret removed a hybrid blob gets a missing-key record and STAYS on the relay (not acked)', async ({ page, request }) => {
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Alice Held Row');
      const { aliceFp } = await seedAliceWithBob(page);
      expect(await removePqKeys(page, aliceFp)).toBe(true);
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: HYBRID_SHAPED })).toBe(200);

      await expect.poll(async () => (await deadLetters(page, aliceFp)).length, { timeout: 40_000 }).toBe(1);
      const [row] = await deadLetters(page, aliceFp);
      expect(Object.keys(row).sort()).toEqual(['enc', 'key']);
      expect(JSON.stringify(row)).not.toContain('missing-key');
      // Several more polls: still exactly one record (the first-sighting row is updated in place) and the envelope is still on the relay.
      await page.waitForTimeout(10_000);
      expect(await deadLetters(page, aliceFp)).toHaveLength(1);
      expect(relayCount(aliceFp), 'a held envelope is kept for retry, never acked').toBe(1);
    });
  });
}
