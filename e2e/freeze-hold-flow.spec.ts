import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { makeE2EIdentity, seedAliceWithBob, depositNote } from './fixtures/deposit-note';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * Freeze keep, END TO END in a real browser: the real app shell, the real background poll, the real over-wire note seam (authenticate -> admit/frozen -> open ->
 * store), the real encrypted notes store. The sender is a genuine canonical identity and the note is a genuine signed + sealed wire deposited on the relay, exactly as
 * notes-roundtrip.spec.ts does; the only difference is that the sender is BLOCKED (in Alice's book, blocked flag set). What this proves for a person:
 *  - a note from a blocked contact is no longer thrown away: it is STORED, marked held, and its relay copy is consumed;
 *  - and it is shown NOWHERE: no thread in the Chat tab, no bubble, the default readers return nothing;
 *  - the sender is answered with the same receipt an unblocked contact gets (parity, measured in the same test), not more and not less;
 *  - a stranger's note is still dropped, exactly as before (nothing stored);
 *  - unblocking the sender moves zero rows: the held note stays hidden, and their NEXT note arrives normally.
 * Desktop Chromium only (the unit + store specs hold the rules; the phone matrix for this flow is not run here).
 */
const PASS = 'e2e-passphrase-1234';
const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function genesisReceiver(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PASS);
  await page.getByPlaceholder('Confirm passphrase').fill(PASS);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

/** Set (or clear) the blocked flag on Bob's stored contact THROUGH the app's own contact store (the state the Block action leaves; the Block UI itself is proven by the block-latch specs). */
async function setBlocked(page: Page, bobFp: string, blocked: boolean) {
  await page.evaluate(([id, b]) => window.__fz.setBlocked(id as string, b as boolean), [`e2e-bob-${bobFp.slice(0, 12)}`, blocked]);
}

async function setup(page: Page) {
  await genesisReceiver(page, 'Alice Frozen');
  const seeded = await seedAliceWithBob(page);
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  await page.evaluate(([o, p]) => window.__fz.initApp(o, p), [seeded.aliceFp, PASS]);
  await page.getByTestId('tab-notes').click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
  return seeded;
}

const heldIds = (page: Page, threadId: string) => page.evaluate((t) => window.__fz.allNotes(t).then((rows) => rows.map((r) => `${r.note_id}${(r as { held?: boolean }).held ? ':held' : ''}`).sort()), threadId);

// The Chat tab lights ("Chat, new messages") for an arrival ONLY while another tab is open (app/page.tsx: `if (mainTab !== 'notes') setNotesActivity(true)`), so a
// check that "nothing was announced" is meaningful only when Chat is closed. Galaxy keeps the shell poll bursting, like Chat does.
async function awayFromChat(page: Page) {
  await page.getByTestId('tab-galaxy').click();
  await expect(page.getByRole('tab', { name: 'Chat', exact: true })).toBeVisible();
}

test('HF1 a note from a BLOCKED contact is stored held and shown nowhere; the thread and bubble never appear', async ({ page, request, baseURL }) => {
  test.setTimeout(180_000);
  const { aliceFp, aliceArmoredPub, bob } = await setup(page);
  await setBlocked(page, bob.fingerprint, true);
  await awayFromChat(page);
  const dep = await depositNote(request, { baseURL, sender: bob, recipientFingerprint: aliceFp, recipientPublicKeyArmored: aliceArmoredPub, fields: { body: 'a note from a blocked contact' } });
  expect(dep.status).toBe(200);
  await expect.poll(() => heldIds(page, dep.thread_id), { timeout: 60_000, intervals: [1000] }).toEqual([`${dep.note_id}:held`]);
  const stored = await page.evaluate((t) => window.__fz.allNotes(t), dep.thread_id);
  expect(stored[0].body, 'opened and stored: the plaintext is what the sender wrote').toBe('a note from a blocked contact');
  expect(await page.evaluate((t) => window.__fz.notes(t), dep.thread_id), 'the default reader returns nothing').toEqual([]);
  // nothing is ANNOUNCED: an arrival makes the Chat tab's name "Chat, new messages" (see HF5, which proves this check can fail); a held note must leave it plain.
  // Chat is closed here (awayFromChat), which is the only state in which the ember can light at all.
  await page.waitForTimeout(3_000);
  await expect(page.getByRole('tab', { name: 'Chat, new messages', exact: true })).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'Chat', exact: true })).toBeVisible();
  // the screen: open Chat (it re-reads the store on mount) and nothing arrived, as far as the person can see
  await page.getByTestId('tab-notes').click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
  await expect(page.getByTestId(`notes-thread-${dep.thread_id}`)).toHaveCount(0);
  await expect(page.getByTestId(`notes-bubble-${dep.note_id}`)).toHaveCount(0);
  expect(await page.evaluate(() => window.__fz.threads()), 'no visible thread at all').toEqual([]);
});

test('HF2 a STRANGER\'s note is still dropped exactly as before: nothing is stored, held or otherwise', async ({ page, request, baseURL }) => {
  test.setTimeout(180_000);
  const { aliceFp, aliceArmoredPub } = await setup(page);
  const stranger = await makeE2EIdentity('stranger');
  const dep = await depositNote(request, { baseURL, sender: stranger, recipientFingerprint: aliceFp, recipientPublicKeyArmored: aliceArmoredPub, fields: { body: 'a note from someone not in the book' } });
  expect(dep.status).toBe(200);
  // give the poll several ticks to consume it (1.5 s each), then look: it must have been dropped, not kept
  await page.waitForTimeout(12_000);
  expect(await heldIds(page, dep.thread_id)).toEqual([]);
  expect(await page.evaluate(() => window.__fz.allThreads())).toEqual([]);
});

test('HF3 RECEIPT PARITY in one session: the same sender gets the same number of receipts for a note while blocked (held) as while unblocked', async ({ page, request, baseURL }) => {
  test.setTimeout(240_000);
  const { aliceFp, aliceArmoredPub, bob } = await setup(page);
  const posts: string[] = [];
  await page.route('**/api/relay/envelope**', (route) => { if (route.request().method() === 'POST') posts.push(route.request().url()); return route.continue(); });
  const rk = 'ab'.repeat(32);
  // control: Bob UNBLOCKED, a note that asks for a receipt
  const a = await depositNote(request, { baseURL, sender: bob, recipientFingerprint: aliceFp, recipientPublicKeyArmored: aliceArmoredPub, fields: { body: 'while unblocked', receiptKey: rk } });
  await expect.poll(() => page.evaluate((t) => window.__fz.notes(t).then((r) => r.length), a.thread_id), { timeout: 60_000, intervals: [1000] }).toBe(1);
  await page.waitForTimeout(8_000); // the receipt is queued and leaves on the outbox's own schedule
  const normalReceipts = posts.length;
  expect(normalReceipts, 'PRECONDITION: this setup does produce a receipt for an admitted contact, so the comparison can see one').toBeGreaterThan(0);
  // now BLOCK Bob and send another receipt-asking note
  await setBlocked(page, bob.fingerprint, true);
  const before = posts.length;
  const b = await depositNote(request, { baseURL, sender: bob, recipientFingerprint: aliceFp, recipientPublicKeyArmored: aliceArmoredPub, fields: { body: 'while blocked', receiptKey: rk } });
  await expect.poll(() => heldIds(page, b.thread_id), { timeout: 60_000, intervals: [1000] }).toEqual([`${b.note_id}:held`]);
  await page.waitForTimeout(8_000);
  expect(posts.length - before, 'a held note is answered with exactly as many receipts as an admitted one').toBe(normalReceipts);
});

test('HF4 UNBLOCKING moves zero rows: the held note stays hidden, and the sender\'s NEXT note arrives and shows normally', async ({ page, request, baseURL }) => {
  test.setTimeout(240_000);
  const { aliceFp, aliceArmoredPub, bob } = await setup(page);
  await setBlocked(page, bob.fingerprint, true);
  const held = await depositNote(request, { baseURL, sender: bob, recipientFingerprint: aliceFp, recipientPublicKeyArmored: aliceArmoredPub, fields: { body: 'sent while blocked' } });
  await expect.poll(() => heldIds(page, held.thread_id), { timeout: 60_000, intervals: [1000] }).toEqual([`${held.note_id}:held`]);
  const rowsBefore = await page.evaluate(() => window.__fz.raw());
  await setBlocked(page, bob.fingerprint, false);
  await page.waitForTimeout(6_000); // several poll ticks after the unblock: nothing may move
  expect(await heldIds(page, held.thread_id), 'still held, still hidden').toEqual([`${held.note_id}:held`]);
  expect(await page.evaluate((t) => window.__fz.notes(t), held.thread_id)).toEqual([]);
  expect((await page.evaluate(() => window.__fz.raw())).length, 'no row was added, removed or rewritten by the unblock').toBe(rowsBefore.length);
  const next = await depositNote(request, { baseURL, sender: bob, recipientFingerprint: aliceFp, recipientPublicKeyArmored: aliceArmoredPub, fields: { body: 'sent after the unblock' } });
  const threadBtn = page.getByTestId(`notes-thread-${next.thread_id}`);
  await expect(threadBtn).toBeVisible({ timeout: 60_000 });
  await threadBtn.click();
  await expect(page.getByTestId(`notes-bubble-${next.note_id}`)).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId(`notes-bubble-${held.note_id}`)).toHaveCount(0);
  await expect(page.getByTestId(`notes-thread-${held.thread_id}`), 'and the held note\'s own thread never appears').toHaveCount(0);
});

test('HF5 CONTROL for HF1: the same arrival from an UNBLOCKED contact while Chat is closed DOES light the tab, so the quiet in HF1 is a real result', async ({ page, request, baseURL }) => {
  test.setTimeout(180_000);
  const { aliceFp, aliceArmoredPub, bob } = await setup(page);
  await awayFromChat(page);
  const dep = await depositNote(request, { baseURL, sender: bob, recipientFingerprint: aliceFp, recipientPublicKeyArmored: aliceArmoredPub, fields: { body: 'a note from an unblocked contact' } });
  expect(dep.status).toBe(200);
  await expect(page.getByRole('tab', { name: 'Chat, new messages', exact: true })).toBeVisible({ timeout: 60_000 });
});
