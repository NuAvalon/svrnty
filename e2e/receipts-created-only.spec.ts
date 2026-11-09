import { test, expect, devices, type Page, type Request } from '@playwright/test';
import { makeE2EIdentity, seedAliceWithBob, buildSealedNote, depositRawBlob } from './fixtures/deposit-note';
import { deriveMailboxId } from '../src/lib/relay/mailbox-auth';

/**
 * Delivery receipts are CREATED-ONLY (task #714 R1): the receiving app answers the delivery that CREATED a note row, and no other.
 *
 * Alice's real app-shell poll receives notes Bob "sends" (a real signed + sealed note deposited to her mailbox). Each note carries a receipt key,
 * so a created note makes Alice's page POST one sealed receipt to BOB's mailbox. We count exactly those POSTs from her page.
 *
 *   C0  CONTROL   a first delivery sends ONE receipt (so a zero below means "not sent", not "this harness cannot send")
 *   C1  NEG       the SAME blob delivered again after a reload (the in-memory dedupe is gone) sends NO second receipt
 *   C2  NEG       a different-content rewrite under a stored note_id, after a reload, sends none (first write wins refuses it)
 * Alice's note body in the store is asserted unchanged in C2 (the refusal itself still works).
 */
const PW = 'e2e-passphrase-1234';
const { defaultBrowserType: _ignored, ...pixel7 } = devices['Pixel 7'];
const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'phone', use: pixel7 },
];

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PW);
  await page.getByPlaceholder('Confirm passphrase').fill(PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}
async function reloadAndUnlock(page: Page) {
  await page.goto('/'); // the unlocked session lives in memory only: a reload is a lock, and the receipt outbox's memory goes with it
  await page.getByPlaceholder('Enter passphrase').fill(PW);
  await page.getByPlaceholder('Enter passphrase').press('Enter');
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 60_000 });
}
/** Count the POSTs Alice's page makes to Bob's mailbox (= receipts to Bob). */
function countReceiptsTo(page: Page, bobFp: string) {
  const mailbox = deriveMailboxId(bobFp);
  const hits: string[] = [];
  page.on('request', (r: Request) => {
    if (r.method() !== 'POST' || !r.url().includes('/api/relay/envelope')) return;
    try { if ((JSON.parse(r.postData() ?? '{}') as { mailbox_id?: string }).mailbox_id === mailbox) hits.push(r.url()); } catch { /* not ours */ }
  });
  return hits;
}
const KEY = 'ab'.repeat(32);
const settle = (page: Page, ms = 6000) => page.waitForTimeout(ms); // a few poll cycles (the shell polls about every 1.5 s while bursting)

for (const variant of MATRIX) {
  test.describe(`created-only receipts · ${variant.label}`, () => {
    test.use(variant.use);

    test('C0 control + C1: a first delivery sends ONE receipt; the same blob again after a reload sends none', async ({ page, request }) => {
      test.setTimeout(150_000);
      await genesis(page, 'Alice Receipts');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      const hits = countReceiptsTo(page, bob.fingerprint);
      const built = await buildSealedNote(bob, aliceArmoredPub, { body: 'first and only', noteId: 'rc-note-1', threadId: 'rc-thr-1', receiptKey: KEY });
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: built.blob })).toBe(200);
      await expect.poll(() => hits.length, { timeout: 40_000, message: 'C0 control: the creating delivery must send one receipt' }).toBe(1);
      await settle(page);
      expect(hits.length, 'C0: still exactly one').toBe(1);

      await reloadAndUnlock(page);
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: built.blob })).toBe(200); // the relay hands the SAME blob again
      await settle(page, 10_000); // long enough for the poll to consume it and for any (wrong) receipt to start
      expect(hits.length, 'C1: the redelivery after a reload is not answered again').toBe(1);
    });

    test('C2: a rewrite under a stored note_id, after a reload, sends no receipt and leaves the stored note as it was', async ({ page, request }) => {
      test.setTimeout(150_000);
      await genesis(page, 'Alice Rewrite');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      const hits = countReceiptsTo(page, bob.fingerprint);
      const first = await buildSealedNote(bob, aliceArmoredPub, { body: 'original text', noteId: 'rc-note-2', threadId: 'rc-thr-2', receiptKey: KEY });
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: first.blob })).toBe(200);
      await expect.poll(() => hits.length, { timeout: 40_000 }).toBe(1);

      await reloadAndUnlock(page);
      const rewrite = await buildSealedNote(bob, aliceArmoredPub, { body: 'EDITED later', noteId: 'rc-note-2', threadId: 'rc-thr-2', receiptKey: KEY });
      expect(await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: rewrite.blob })).toBe(200);
      await settle(page, 10_000);
      expect(hits.length, 'C2: the refused rewrite is not answered').toBe(1);

      await page.getByTestId('tab-notes').click();
      await page.getByTestId('notes-thread-rc-thr-2').click();
      await expect(page.getByTestId('notes-bubble-rc-note-2')).toContainText('original text');
      await expect(page.getByTestId('notes-bubble-rc-note-2')).not.toContainText('EDITED later');
    });
  });
}
