import { test, expect, type Browser, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard } from '../src/lib/identity/identity-card-sign';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

const PASS = 'e2e-passphrase-1234';
const EXPORT_PW = 'export-e2e-pass-5678';

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
  // Two contacts here (the original helper assumed one): a click on this row opens THIS person's card, switches to it from another's, or closes it if it was already open.
  await rowOf(page, who).first().click();
  if (!(await bookCard.count())) await rowOf(page, who).first().click();
  await expect(bookCard).toHaveCount(1);
  await (await openCardMenu(page)).getByRole('menuitem', { name: 'Remove', exact: true }).click();
  await confirmAction(page, 'remove');
  await expect(rowOf(page, who)).toHaveCount(0);
}

async function toPassphraseStep(page: Page) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(PASS);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByTestId('vault-export-passphrase')).toBeVisible({ timeout: 15_000 });
}

async function finishExport(page: Page, dest: string) {
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  await (await downloadPromise).saveAs(dest);
}

async function restoreOnNewDevice(browser: Browser, vaultPath: string) {
  const ctx = await browser.newContext({ bypassCSP: true });
  const p = await ctx.newPage();
  await p.goto('/');
  await p.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await p.setInputFiles('[data-testid="restore-file-input"]', vaultPath);
  await p.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
  await p.getByRole('button', { name: /^restore identity$/i }).click();
  await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
  await p.addScriptTag({ content: bundle('e2e/helpers/block-latch-harness.ts') });
  await p.evaluate((pw) => window.__bl.init(pw), EXPORT_PW); // a vault restore leaves the vault passphrase as the device passphrase
  return { ctx, p };
}


const NOTICE = "You removed this person before. They're back in your contacts now, and they weren't told you'd removed them. Your backups still record that you removed them.";
const HELPER = "Keep them, and backups you make from now on won't record it.";

/** Click this person's row until THEIR card is the open one in the book (a row click toggles). */
async function openBookCard(page: Page, who: string) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  const bookCard = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  await rowOf(page, who).first().click();
  if (!(await bookCard.count())) await rowOf(page, who).first().click();
  await expect(bookCard).toHaveCount(1);
  await expect(bookCard).toContainText(who);
  return bookCard;
}

async function closeBookCard(page: Page, who: string) {
  const bookCard = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  if (await bookCard.count()) {
    await rowOf(page, who).first().click();
    await expect(bookCard).toHaveCount(0);
  }
}

const idsOf = (list: string[] | 'absent' | 'unreadable', x: string, y: string) => (Array.isArray(list) ? list.map((f) => (f === x ? 'X' : f === y ? 'Y' : '?')).sort() : list);

// #912: the owner's private contact book shows "You removed this person before" for a removed-then-re-added person. Keep them takes them off the removed list (the drop's one caller); the Galaxy never shows it.
test('#912 notice: shown in the contact book, not on the Galaxy tab; Keep them drops only that person; the drop survives export and restore', async ({ browser }, testInfo) => {
  test.setTimeout(420_000);
  const x = await realCard('Rejoined Xavier');
  const y = await realCard('Removed Yvonne');
  const ctxA = await browser.newContext({ bypassCSP: true });
  const a = await ctxA.newPage();
  await genesis(a, 'Gina');
  await importCard(a, x.card);
  await importCard(a, y.card);
  await a.addScriptTag({ content: bundle('e2e/helpers/block-latch-harness.ts') });
  await a.evaluate((p) => window.__bl.init(p), PASS);
  const owner = await a.evaluate(() => window.__bl.ownerFp());
  await a.evaluate((o) => window.__bl.initRecord(o), owner);

  await removeViaUI(a, 'Rejoined Xavier');
  await removeViaUI(a, 'Removed Yvonne');
  await importCard(a, x.card); // re-add X by card

  // The contact LIST row carries no marker (copy row 314c): the row says the name and nothing about a removal.
  await a.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(rowOf(a, 'Rejoined Xavier').first()).toBeVisible();
  expect((await rowOf(a, 'Rejoined Xavier').first().innerText()).toLowerCase()).not.toMatch(/removed|before|blocked/);

  // In the book: the notice, word for word, with the two buttons and the helper line; no "Leave it".
  const card = await openBookCard(a, 'Rejoined Xavier');
  const notice = card.getByTestId('removed-before-notice');
  await expect(notice).toBeVisible();
  await expect(card.getByTestId('removed-before-text')).toHaveText(NOTICE);
  await expect(card.getByTestId('removed-before-helper')).toHaveText(HELPER);
  await expect(card.getByTestId('removed-before-keep')).toHaveText('Keep them');
  await expect(card.getByTestId('removed-before-remove-again')).toHaveText('Remove them again');
  await expect(notice.getByText(/leave it/i)).toHaveCount(0);
  // X was re-added NORMALLY: in the book, not blocked, and still on the removed list (the notice reads that entry).
  const dump0 = await a.evaluate((o) => window.__bl.dump(o), owner);
  const xRec = dump0.find((c) => c.fingerprint === x.fingerprint);
  expect(xRec, 'X is back in the book').toBeTruthy();
  expect(!!xRec!.blocked || !!xRec!.metaBlocked, 'X is NOT blocked').toBe(false);
  expect(idsOf(await a.evaluate((o) => window.__bl.removedList(o), owner), x.fingerprint, y.fingerprint)).toEqual(['X', 'Y']);

  // The Galaxy: a re-added person is not a star until the owner trusts them ("0 connections"), so there is no Galaxy card to open for X here. What the browser CAN show: with X in the book AND on the
  // removed list, the Galaxy tab carries none of the notice's words. That the Galaxy CARD never renders it is pinned in the source (TrustMap never passes the opt-in prop; mutants M2/M3/M11).
  await a.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await expect(a.getByRole('img', { name: /Galaxy: 0 connections/ })).toBeVisible({ timeout: 20_000 });
  await expect(a.locator('[data-testid="trust-node"][data-name="Rejoined Xavier"]')).toHaveCount(0);
  await expect(a.getByTestId('removed-before-notice')).toHaveCount(0);
  expect((await a.locator('body').innerText()).toLowerCase()).not.toContain('you removed this person before');

  // Keep them: the notice goes, the list loses X and ONLY X.
  await openBookCard(a, 'Rejoined Xavier');
  await a.getByTestId('removed-before-keep').click();
  await expect(a.getByTestId('removed-before-notice')).toHaveCount(0, { timeout: 15_000 });
  expect(idsOf(await a.evaluate((o) => window.__bl.removedList(o), owner), x.fingerprint, y.fingerprint)).toEqual(['Y']);
  expect(await a.evaluate(([o, f]) => window.__bl.latchKind(o, f), [owner, y.fingerprint]), 'Y stays latched').toBe('removed');
  // Close and reopen the card: no notice comes back.
  await closeBookCard(a, 'Rejoined Xavier');
  await openBookCard(a, 'Rejoined Xavier');
  await expect(a.getByTestId('removed-before-notice')).toHaveCount(0);

  // Export and restore on a NEW device: X is in the book, not on the list, not latched; Y (control) is still on the list and latched.
  await toPassphraseStep(a);
  const vault = testInfo.outputPath('p912-notice.svrnty');
  await finishExport(a, vault);
  await ctxA.close();
  const { ctx, p } = await restoreOnNewDevice(browser, vault);
  const ownerB = await p.evaluate(() => window.__bl.ownerFp());
  expect(ownerB).toBe(owner);
  const dumpB = await p.evaluate((o) => window.__bl.dump(o), ownerB);
  expect(dumpB.some((c) => c.fingerprint === x.fingerprint), 'X is in the restored book').toBe(true);
  expect(idsOf(await p.evaluate((o) => window.__bl.removedList(o), ownerB), x.fingerprint, y.fingerprint), 'the restored list no longer records X').toEqual(['Y']);
  expect(await p.evaluate(([o, f]) => window.__bl.latchKind(o, f), [ownerB, x.fingerprint]), 'X is not latched').not.toBe('removed');
  expect(await p.evaluate(([o, f]) => window.__bl.latchKind(o, f), [ownerB, y.fingerprint]), 'CONTROL: Y is latched').toBe('removed');
  await ctx.close();
});

test('#912 notice: Remove them again is the normal Remove (X leaves the book, stays on the list); re-adding shows the notice again', async ({ browser }) => {
  test.setTimeout(300_000);
  const x = await realCard('Again Xenia');
  const ctx = await browser.newContext({ bypassCSP: true });
  const a = await ctx.newPage();
  await genesis(a, 'Gina');
  await importCard(a, x.card);
  await a.addScriptTag({ content: bundle('e2e/helpers/block-latch-harness.ts') });
  await a.evaluate((p) => window.__bl.init(p), PASS);
  const owner = await a.evaluate(() => window.__bl.ownerFp());
  await a.evaluate((o) => window.__bl.initRecord(o), owner);
  await removeViaUI(a, 'Again Xenia');
  await importCard(a, x.card);
  await openBookCard(a, 'Again Xenia');
  await a.getByTestId('removed-before-remove-again').click();
  await confirmAction(a, 'remove');
  await expect(rowOf(a, 'Again Xenia')).toHaveCount(0);
  expect(await a.evaluate((o) => window.__bl.removedList(o), owner)).toContain(x.fingerprint);
  await importCard(a, x.card); // back again
  await openBookCard(a, 'Again Xenia');
  await expect(a.getByTestId('removed-before-notice')).toBeVisible();
  await ctx.close();
});
