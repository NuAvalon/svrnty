import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard } from '../src/lib/identity/identity-card-sign';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * Block and Remove set the beacon LATCH, in a REAL browser: real IndexedDB, real AES-GCM, the real contact store and the real helpers both screens call
 * (setContactBlocked, removeContactWithLatch). Nothing is stubbed. The unit tests hold the rules (src/lib/trust/block-latch.test.ts); this proves the REAL store honours them:
 *  - a Block writes the latch row (sealed, under beacon_latch:) AND the record entry, and the flag; the person is told it finished;
 *  - a Block on an identity with NO suppression record yet (today's dev: the genesis init is not wired) is NOT reported as unfinished: an absent record already suppresses everyone;
 *  - Unblock removes the record entry and the flag and LEAVES the latch, and the start-up repair does not write the block back;
 *  - Remove records the removal, latches, then deletes; a keyless contact is simply deleted;
 *  - the start-up reverse pass latches people the record or the removed list names (a restore that died before its rebuild);
 *  - the forward repair adds a blocked contact missing from the record.
 */
const PASS = 'e2e-passphrase-1234';
const OWNER = 'owner-block-latch-e2e';
const FP1 = '1'.repeat(64);
const FP2 = '2'.repeat(64);
const FP3 = '3'.repeat(64);

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function genesis(page: Page, name: string) {
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

async function setup(page: Page) {
  await genesis(page, 'Gina');
  await page.addScriptTag({ content: bundle('e2e/helpers/block-latch-harness.ts') });
  await page.evaluate((p) => window.__bl.init(p), PASS);
}

test('DIAGNOSTIC: a Block on an identity with NO suppression record yet finishes (an absent record already suppresses everyone), and the latch + flag are written', async ({ page }) => {
  test.setTimeout(150_000);
  await setup(page);
  const id = await page.evaluate(([o, n, f]) => window.__bl.add(o, n, f), [OWNER, 'Ada', FP1]);
  expect(await page.evaluate((o) => window.__bl.record(o), OWNER), 'precondition: no record exists (the genesis init is not wired on this tree)').toBeNull();
  const r = await page.evaluate(([o, i, f]) => window.__bl.block(o, i, f, true), [OWNER, id, FP1]);
  expect(r.finished, 'the Block must not be reported as unfinished: the absent record is over-dark, not a gap').toBe(true);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [OWNER, FP1])).toBe('removed');
  expect(await page.evaluate((i) => window.__bl.isBlocked(i), id)).toBe(true);
  expect(await page.evaluate(() => window.__bl.latchRows())).toBe(1);
});

test('Block with a record: latch row + record entry + flag; Unblock removes the entry and the flag, LEAVES the latch, and the start-up repair does not write it back', async ({ page }) => {
  test.setTimeout(150_000);
  await setup(page);
  await page.evaluate((o) => window.__bl.initRecord(o), OWNER);
  const id = await page.evaluate(([o, n, f]) => window.__bl.add(o, n, f), [OWNER, 'Ada', FP1]);
  const r = await page.evaluate(([o, i, f]) => window.__bl.block(o, i, f, true), [OWNER, id, FP1]);
  expect(r.finished).toBe(true);
  expect((await page.evaluate((o) => window.__bl.record(o), OWNER))?.persons).toEqual([FP1]);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [OWNER, FP1])).toBe('removed');

  await page.evaluate(([o, i, f]) => window.__bl.block(o, i, f, false), [OWNER, id, FP1]);
  expect(await page.evaluate((i) => window.__bl.isBlocked(i), id)).toBe(false);
  expect((await page.evaluate((o) => window.__bl.record(o), OWNER))?.persons, 'the record entry is gone').toEqual([]);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [OWNER, FP1]), 'the latch stays (tighter)').toBe('removed');

  // "restart": both repair passes, as at unlock
  expect(await page.evaluate((o) => window.__bl.repair(o), OWNER)).toBe('nothing-to-repair');
  await page.evaluate((o) => window.__bl.relatch(o), OWNER);
  expect((await page.evaluate((o) => window.__bl.record(o), OWNER))?.persons, 'the reversed block was NOT written back').toEqual([]);
});

test('Remove: the removal is recorded, the pair latched, the contact deleted; a keyless contact is simply deleted (never refused)', async ({ page }) => {
  test.setTimeout(150_000);
  await setup(page);
  const a = await page.evaluate(([o, n, f]) => window.__bl.add(o, n, f), [OWNER, 'Grace', FP2]);
  const keyless = await page.evaluate(([o, n]) => window.__bl.add(o, n, ''), [OWNER, 'Keyless']);
  await page.evaluate(([o, i, f]) => window.__bl.remove(o, i, f), [OWNER, a, FP2]);
  expect(await page.evaluate((i) => window.__bl.has(i), a), 'deleted').toBe(false);
  expect(await page.evaluate((o) => window.__bl.removedList(o), OWNER), 'the removal is in the list').toEqual([FP2]);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [OWNER, FP2])).toBe('removed');
  await page.evaluate(([o, i]) => window.__bl.remove(o, i, ''), [OWNER, keyless]);
  expect(await page.evaluate((i) => window.__bl.has(i), keyless), 'a keyless contact is deleted, not refused').toBe(false);
  expect(await page.evaluate((o) => window.__bl.removedList(o), OWNER), 'and adds nothing to the list').toEqual([FP2]);
});

test('start-up reverse pass: people the record or the removed list names, with NO latch (a restore that died before its rebuild), are latched', async ({ page }) => {
  test.setTimeout(150_000);
  await setup(page);
  await page.evaluate(({ o, p }) => window.__bl.plantRecord(o, p), { o: OWNER, p: [FP3] });
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [OWNER, FP3]), 'precondition: named, not latched').toBeNull();
  const r = await page.evaluate((o) => window.__bl.relatch(o), OWNER);
  expect(r.outcome === 'relatched' || r.outcome === 'partial', `outcome ${r.outcome}`).toBe(true);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [OWNER, FP3])).toBe('removed');
});

/** A REAL signed identity card with a canonical (64-hex) fingerprint, built from a throwaway identity (same recipe as e2e/beacon-card-import-compat.spec.ts). */
async function realCard(name: string): Promise<{ card: string; fingerprint: string }> {
  const pass = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: 'block-latch@x.test' }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const card = await signIdentityCard({
    version: '1.1', type: 'identity-exchange', created_at: new Date().toISOString(),
    identity: {
      fingerprint, display_name: name, public_key: publicKey, email: '',
      pq_sig_public_key: uint8ToBase64(pq.signing.publicKey), pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), next_authority_commitment: '',
    },
  } as never, privateKey, pass);
  return { card: JSON.stringify(card), fingerprint };
}

async function importCard(page: Page, text: string): Promise<void> {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.locator('button:has-text("Import Contact"):not([data-testid="import-contacts-trigger"])').first().click();
  await page.getByPlaceholder('Paste the signed identity package here...').fill(text);
  await page.getByRole('button', { name: /Verify & Import/ }).click();
  const dlg = page.locator('[role="dialog"]').filter({ hasText: /Verify & Import|Import/ }).first();
  await expect(dlg.getByText(/added successfully/i).first()).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press('Escape');
}

const rowOf = (page: Page, who: string) => page.locator('[data-testid="contact-row"]').filter({ hasText: who });

async function openCardMenu(page: Page) {
  const card = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  await expect(card).toBeVisible();
  const toggle = card.getByTestId('card-actions-toggle');
  await toggle.scrollIntoViewIfNeeded();
  await toggle.click({ timeout: 10_000 });
  const menu = card.getByTestId('card-actions-toggle-menu');
  await expect(menu).toBeVisible();
  return menu;
}

async function confirmAction(page: Page, kind: string) {
  const confirm = page.getByTestId('trust-action-confirm');
  await expect(confirm).toHaveAttribute('data-action-kind', kind);
  await confirm.getByTestId('trust-action-confirm-btn').click();
  await expect(confirm).toHaveCount(0);
}

// The same navigation e2e/blocked-card-menu-unblock.spec.ts uses: the card menu, and the Blocked view for a blocked contact.
async function blockViaUI(page: Page, who: string) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await rowOf(page, who).first().click();
  await (await openCardMenu(page)).getByRole('menuitem', { name: 'Block', exact: true }).click();
  await confirmAction(page, 'block');
  await expect(rowOf(page, who)).toHaveCount(0); // gone from the main book
}

async function unblockViaUI(page: Page, who: string) {
  await page.getByRole('button', { name: 'Book options' }).click();
  await page.getByRole('menuitem', { name: /view blocked contacts/i }).click();
  const blockedRow = rowOf(page, who).first();
  await expect(blockedRow).toBeVisible({ timeout: 15_000 });
  // A row click TOGGLES its card, and the card we blocked from may still be open: pin the state (closed), then open it.
  const bookCard = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  if (await bookCard.count()) {
    await blockedRow.click();
    await expect(bookCard).toHaveCount(0);
  }
  await blockedRow.click();
  await (await openCardMenu(page)).getByRole('menuitem', { name: 'Unblock', exact: true }).click();
  await confirmAction(page, 'unblock');
  await page.getByRole('button', { name: 'Book options' }).click();
  await page.getByRole('menuitem', { name: /hide blocked contacts/i }).click();
}

async function removeViaUI(page: Page, who: string) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(rowOf(page, who).first()).toBeVisible({ timeout: 15_000 });
  const bookCard = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  if (await bookCard.count()) {
    await rowOf(page, who).first().click();
    await expect(bookCard).toHaveCount(0);
  }
  await rowOf(page, who).first().click();
  await (await openCardMenu(page)).getByRole('menuitem', { name: 'Remove', exact: true }).click();
  await confirmAction(page, 'remove');
  await expect(rowOf(page, who)).toHaveCount(0);
}

test('REAL UI, REAL contact: a card is imported, then Block / Unblock / Remove through the contact book write the latch, the record and the removed list as designed', async ({ page }) => {
  test.setTimeout(300_000);
  const { card, fingerprint } = await realCard('Mallory Latch');
  await genesis(page, 'Gina');
  await importCard(page, card);
  await page.addScriptTag({ content: bundle('e2e/helpers/block-latch-harness.ts') });
  await page.evaluate((p) => window.__bl.init(p), PASS);
  const owner = await page.evaluate(() => window.__bl.ownerFp());
  await page.evaluate((o) => window.__bl.initRecord(o), owner);
  const dump = await page.evaluate((o) => window.__bl.dump(o), owner);
  expect(dump.length).toBe(1);
  expect(dump[0].fingerprint, 'a REAL imported contact exposes its canonical fingerprint (what the repair reads)').toBe(fingerprint);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint]), 'precondition: no latch yet').toBeNull();

  await blockViaUI(page, 'Mallory Latch');
  expect(await page.evaluate((i) => window.__bl.isBlocked(i), dump[0].id), 'the flag').toBe(true);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint]), 'Block set the latch').toBe('removed');
  expect((await page.evaluate((o) => window.__bl.record(o), owner))?.persons, 'and the record entry').toEqual([fingerprint]);
  await expect(page.getByText(/Blocking didn.t finish/i), 'a finished Block shows no failure').toHaveCount(0);

  await unblockViaUI(page, 'Mallory Latch');
  expect(await page.evaluate((i) => window.__bl.isBlocked(i), dump[0].id)).toBe(false);
  expect((await page.evaluate((o) => window.__bl.record(o), owner))?.persons, 'Unblock removed the record entry').toEqual([]);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint]), 'and LEFT the latch').toBe('removed');
  await page.evaluate((p) => window.__bl.init(p), PASS); // an unlock: both repair passes run
  expect((await page.evaluate((o) => window.__bl.record(o), owner))?.persons, 'the unlock did not write the reversed block back').toEqual([]);

  await removeViaUI(page, 'Mallory Latch');
  expect(await page.evaluate((o) => window.__bl.removedList(o), owner), 'Remove recorded the removal').toEqual([fingerprint]);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint])).toBe('removed');
});

test('forward repair on a REAL contact: the blocked flag is set but the record lacks the person (state B3) -> repaired; an unblocked contact is not added; the export gate passes', async ({ page }) => {
  test.setTimeout(300_000);
  const a = await realCard('Blocked Real');
  const b = await realCard('Free Real');
  await genesis(page, 'Gina');
  await importCard(page, a.card);
  await importCard(page, b.card);
  await page.addScriptTag({ content: bundle('e2e/helpers/block-latch-harness.ts') });
  await page.evaluate((p) => window.__bl.init(p), PASS);
  const owner = await page.evaluate(() => window.__bl.ownerFp());
  await page.evaluate((o) => window.__bl.initRecord(o), owner);
  const dump = await page.evaluate((o) => window.__bl.dump(o), owner);
  const blocked = dump.find((c) => c.fingerprint === a.fingerprint)!;
  expect(blocked, 'both real contacts expose their fingerprint').toBeTruthy();
  await page.evaluate((i) => window.__bl.flagOnly(i, true), blocked.id); // the flag, but no record write
  expect((await page.evaluate((o) => window.__bl.record(o), owner))?.persons).toEqual([]);
  expect(await page.evaluate((o) => window.__bl.repair(o), owner)).toBe('repaired');
  expect((await page.evaluate((o) => window.__bl.record(o), owner))?.persons, 'only the BLOCKED contact is added').toEqual([a.fingerprint]);
  expect(await page.evaluate((o) => window.__bl.gate(o), owner)).toBe('ok');
});

test('BOOK GOVERNS, real store: Remove, re-add the same card, a Trust tap clears the latch, the start-up pass does NOT latch them again; a removed id NOT in the book still latches', async ({ page }) => {
  test.setTimeout(300_000);
  const { card, fingerprint } = await realCard('Rejoin Real');
  await genesis(page, 'Gina');
  await importCard(page, card);
  await page.addScriptTag({ content: bundle('e2e/helpers/block-latch-harness.ts') });
  await page.evaluate((p) => window.__bl.init(p), PASS);
  const owner = await page.evaluate(() => window.__bl.ownerFp());
  const first = (await page.evaluate((o) => window.__bl.dump(o), owner))[0];
  await page.evaluate(([o, i, f]) => window.__bl.remove(o, i, f), [owner, first.id, fingerprint]);
  expect(await page.evaluate((o) => window.__bl.removedList(o), owner)).toEqual([fingerprint]);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint]), 'Remove latched').toBe('removed');

  // NOT in the book: a start-up pass with the latch missing latches the removed id again
  await page.evaluate(([o, f]) => window.__bl.trustTapClears(o, f), [owner, fingerprint]);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint])).toBeNull();
  await page.evaluate((p) => window.__bl.init(p), PASS); // an unlock: both repair passes
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint]), 'a removed id that is NOT in the book still latches').toBe('removed');

  // IN the book again: re-add the same card, a Trust tap clears the latch, and the next start leaves it alone
  await importCard(page, card);
  expect((await page.evaluate((o) => window.__bl.dump(o), owner)).length, 're-added').toBe(1);
  await page.evaluate(([o, f]) => window.__bl.trustTapClears(o, f), [owner, fingerprint]);
  await page.evaluate((p) => window.__bl.init(p), PASS);
  expect(await page.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, fingerprint]), 'the start-up pass did NOT undo the Trust tap').toBeNull();
  expect(await page.evaluate((o) => window.__bl.removedList(o), owner), 'the list still names them (append-only)').toEqual([fingerprint]);
});
