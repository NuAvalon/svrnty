import { test, expect, devices, type Page } from '@playwright/test';
import { seedAliceWithBob } from './fixtures/deposit-note';
import { deriveMailboxId } from '../src/lib/relay/mailbox-auth';

/**
 * S14 (HNDL, Nov-5 PQ gate) — a LEGACY contact (stored before canonical-only cards: no ML-KEM leg) must be
 * SKIPPED on a note send, never downgraded to classical, and the user must be told the real remedy.
 *
 * Flint (lane:svrnty): the 'no-pq-kem' branch IS reachable for notes + contact-update because old contact
 * records can still sit in users' address books (client-side IndexedDB). Real browser, real Notes UI, real
 * sendNoteToPeer; the only seeded thing is the contact record (raw IndexedDB, same path as demo-arc).
 *
 *  • NEGATIVE: contact with the kem leg stripped → status line names the updated-contact-card remedy, and NO
 *    POST to /api/relay/envelope for that contact's mailbox (no classical fallback on the wire).
 *  • POSITIVE CONTROL: the same flow with the kem leg present → exactly one POST, a PQ-hybrid package
 *    (raw JSON {v:1,…}, not armored PGP) → 'Sent to the relay'. Without it the negative proves nothing.
 *
 * Matrix: desktop Chromium + mobile-Chromium (Pixel 7, hardened-mobile center). Other engines: not covered.
 */

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 }); // keygen (PQ) is slow on a cold dev server; other specs use 30s and flake the same way
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

/**
 * Resolves when the shell's first relay poll answered. The poll runs buildConsumeDeps, which UNLOCKS the notes store
 * before it fetches the queue; a send before that throws 'Notes store locked' (observed: ~1 in 12 runs without this
 * wait). Register it BEFORE genesis so the first poll cannot slip past.
 */
function firstShellPoll(page: Page) {
  return page.waitForResponse((r) => r.url().includes('/api/relay/queue'), { timeout: 90_000 });
}

/** Turn a seeded contact into a LEGACY one: drop its ML-KEM leg (keep key + fingerprint), via raw IndexedDB. */
async function stripKemLeg(page: Page, contactFp: string) {
  await page.evaluate(async (fp: string) => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const r = indexedDB.open('svrnty');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('contacts', 'readwrite');
      const store = tx.objectStore('contacts');
      const all = store.getAll();
      all.onsuccess = () => {
        const rec = (all.result as Array<Record<string, unknown>>).find((c) => c.fingerprint === fp);
        if (!rec) return reject(new Error('stripKemLeg: seeded contact not found'));
        delete rec.pq_kem_public_key;
        store.put(rec);
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  }, contactFp);
}

const pixel7Mobile: Record<string, unknown> = { ...devices['Pixel 7'] };
delete pixel7Mobile.defaultBrowserType; // a describe-level use() may not switch the browser engine
const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7)', use: pixel7Mobile },
];

for (const variant of MATRIX) {
  test.describe(`S14 skipped-send copy · ${variant.label}`, () => {
    test.use(variant.use);

    async function sendNoteToBob(page: Page, bobFp: string, body: string) {
      const posts: Array<{ mailbox_id: string; blob: string }> = [];
      page.on('request', (req) => {
        if (req.method() === 'POST' && req.url().includes('/api/relay/envelope')) {
          try {
            posts.push(JSON.parse(req.postData() ?? '{}'));
          } catch {
            posts.push({ mailbox_id: '?unparsed', blob: '' });
          }
        }
      });
      await page.getByTestId('tab-notes').click();
      const panel = page.getByTestId('notes-inbox');
      await expect(panel).toBeVisible();
      await panel.getByTestId('notes-contact-picker').selectOption(bobFp);
      await panel.getByTestId('notes-compose').fill(body);
      await panel.getByTestId('notes-send-btn').click();
      await expect(panel.getByTestId('notes-send-status')).toBeVisible({ timeout: 20_000 });
      return { panel, bobPosts: () => posts.filter((p) => p.mailbox_id === deriveMailboxId(bobFp)) };
    }

    test('NEGATIVE: a legacy contact (no kem leg) is skipped with the updated-card remedy — nothing goes on the wire', async ({ page }) => {
      test.setTimeout(240_000);
      const firstPoll = firstShellPoll(page);
      await genesis(page, 'Alice Legacy');
      const { bob } = await seedAliceWithBob(page);
      await stripKemLeg(page, bob.fingerprint);

      await firstPoll; // notes store is unlocked once the first poll has answered
      const { panel, bobPosts } = await sendNoteToBob(page, bob.fingerprint, 'hello legacy contact');

      await expect(panel.getByTestId('notes-send-status')).toHaveText(
        /^Not sent\. Saved on this device\. .+ needs to share an updated contact card \(security upgrade\)\. Ask them to re-share, then re-add\.$/,
      );
      expect(bobPosts(), 'NO deposit to the legacy contact’s mailbox: no classical fallback on the wire').toHaveLength(0);
      await expect(panel.getByText(/^Delivered$/)).toHaveCount(0);
      await expect(panel.getByText(/quantum|PQ-secure/i)).toHaveCount(0);
    });

    test('CONTROL: the same contact WITH its kem leg is sent as a PQ-hybrid package (so the negative is not vacuous)', async ({ page }) => {
      test.setTimeout(240_000);
      const firstPoll = firstShellPoll(page);
      await genesis(page, 'Alice Control');
      const { bob } = await seedAliceWithBob(page);

      await firstPoll;
      const { panel, bobPosts } = await sendNoteToBob(page, bob.fingerprint, 'hello pq contact');

      await expect(panel.getByTestId('notes-send-status')).toHaveText('Sent to the relay');
      expect(bobPosts()).toHaveLength(1);
      const blob = bobPosts()[0].blob;
      expect(blob).not.toContain('BEGIN PGP MESSAGE');
      expect(JSON.parse(blob).v, 'a raw-JSON hybrid MailboxEnvelopePackage').toBe(1);
    });
  });
}

