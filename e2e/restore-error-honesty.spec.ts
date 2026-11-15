import { test, expect, type Page, type Browser } from '@playwright/test';
import { writeFileSync } from 'node:fs';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { RESTORE_MESSAGES } from '../src/lib/identity/restore-errors';

/**
 * What the restore screen says when a restore fails, through the real screens.
 *
 *  1. An old-format FULL backup (the app's own backup object, encrypted the old way with node:crypto) restores on a fresh device with the right password,
 *     and the screen says the device now unlocks with that password. (Before the full-backup restore it ended in a dead end: a message that was not the wrong-password one.)
 *  2. A genuinely WRONG password still says the password did not open the file (the fix must not over-correct).
 *  3. A file with a password method this version does not read shows its own sentence, not the wrong-password one.
 *
 * Before the fix, 1 and 3 both showed the wrong-password sentence (the handler tested the error's TEXT for the words password/passphrase/decrypt).
 * Needs a PRODUCTION build (`next build && next start`). The harness that reads the app's backup needs the page's script policy off (bypassCSP).
 */

const UNLOCK_PW = 'unlock-e2e-pass-1234';
const FILE_PW = 'restore-e2e-pass-5678';
test.setTimeout(240_000);
test.describe.configure({ mode: 'serial' });

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

declare global { interface Window { __bk: { all(fp: string, pw: string): Promise<unknown> } } }

async function mint(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Restore Honesty E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 60_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}

/** An envelope in the OLD format, built with node:crypto only: PBKDF2-SHA256, 100,000 iterations, AES-256-GCM. */
function oldFormat(plain: string, password: string, extra: Record<string, unknown>) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, 100_000, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plain)), c.final(), c.getAuthTag()]);
  return { ...extra, algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA256-100k', salt: salt.toString('base64'), iv: iv.toString('base64'), data: ct.toString('base64') };
}

/** Pick the file at the gate, enter the password, press the button, and return the error line the screen shows. */
async function restoreAndReadError(browser: Browser, file: string, password: string): Promise<string> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
  await page.getByPlaceholder('Encryption password from export').fill(password);
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  const error = page.getByText(/didn't open this file|has no password yet|can't read|Something went wrong|isn't a backup/i).first();
  await expect(error).toBeVisible({ timeout: 60_000 });
  const text = (await error.innerText()).trim();
  await ctx.close();
  return text;
}

let backup: Record<string, unknown> | null = null;

test.beforeAll(async ({ browser }) => {
  const ctx = await browser.newContext({ bypassCSP: true });
  const page = await ctx.newPage();
  await mint(page);
  await page.addScriptTag({ content: bundle('e2e/helpers/backup-export-harness.ts') });
  // the owner's fingerprint, from the identity the app just minted
  const ident = await page.evaluate(() => new Promise<string | null>((resolve) => {
    const open = indexedDB.open('svrnty');
    open.onerror = () => resolve(null);
    open.onsuccess = () => {
      const db = open.result;
      try {
        const all = db.transaction('identities').objectStore('identities').getAllKeys();
        all.onsuccess = () => { db.close(); resolve((all.result[0] as string) ?? null); };
        all.onerror = () => { db.close(); resolve(null); };
      } catch { db.close(); resolve(null); }
    };
  }));
  expect(ident, 'the minted identity is in the app\'s own store').toBeTruthy();
  backup = (await page.evaluate(([f, pw]) => window.__bk.all(f, pw), [ident!, UNLOCK_PW])) as Record<string, unknown>;
  expect((backup as { identity?: unknown }).identity).toBeTruthy();
  await ctx.close();
});

test('1. an old-format full backup with the right password restores on a fresh device: no error, and the screen says the device now unlocks with that password', async ({ browser }, testInfo) => {
  const b = { ...backup! }; delete b.vault;
  const file = testInfo.outputPath('full-old.json');
  writeFileSync(file, JSON.stringify(oldFormat(JSON.stringify(b), FILE_PW, { type: 'svrnty-full-backup', version: '1.0', encrypted: true })));
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
  await page.getByPlaceholder('Encryption password from export').fill(FILE_PW);
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await expect(page.getByText(RESTORE_MESSAGES.deviceUsesFilePassword)).toBeVisible({ timeout: 60_000 });
  const body = await page.locator('body').innerText();
  console.log('[restore-honesty] full backup, RIGHT password: restored, device line shown');
  expect(body).not.toMatch(/incorrect|didn't open this file|Something went wrong/i);
  await ctx.close();
});

test('2. a genuinely WRONG password still says so (the fix does not over-correct)', async ({ browser }, testInfo) => {
  const b = { ...backup! }; delete b.vault;
  const file = testInfo.outputPath('full-old-2.json');
  writeFileSync(file, JSON.stringify(oldFormat(JSON.stringify(b), FILE_PW, { type: 'svrnty-full-backup', version: '1.0', encrypted: true })));
  const shown = await restoreAndReadError(browser, file, 'definitely-the-wrong-pass');
  console.log(`[restore-honesty] full backup, WRONG password: "${shown}"`);
  expect(shown).toBe(RESTORE_MESSAGES.wrongPassword);
});

test('3. a file with a password method this version does not read shows its own sentence, not the wrong-password one', async ({ browser }, testInfo) => {
  const env = oldFormat(JSON.stringify({ x: 1 }), FILE_PW, { type: 'svrnty-full-backup', version: '1.0', encrypted: true });
  const file = testInfo.outputPath('full-unknown-kdf.json');
  writeFileSync(file, JSON.stringify({ ...env, kdf: 'scrypt-n14' }));
  const shown = await restoreAndReadError(browser, file, FILE_PW);
  console.log(`[restore-honesty] unknown password method: "${shown}"`);
  expect(shown).toBe(RESTORE_MESSAGES.unsupportedFormat);
  expect(shown).not.toMatch(/incorrect/i);
});

// The copy owner's wording for a key-only restore (ledger row 170). Kept as a literal here so the spec does not read it from the code under test.
const KEY_ONLY_SENTENCE = 'Your identity key is saved on this device. This file holds only the key, not your profile or contacts. To bring those back, restore a full backup file.';

test('4. a KEY-ONLY file restored on a fresh device says what it did and what it did not bring back (silence would be a claim by omission)', async ({ browser }, testInfo) => {
  const b = backup as { identity?: { identity?: { fingerprint?: string } }; keys?: { privateKey?: string; passphrase?: string } };
  const fingerprint = b.identity?.identity?.fingerprint;
  expect(fingerprint && b.keys?.privateKey, 'the exported backup carries the owner\'s key').toBeTruthy();
  const file = testInfo.outputPath('keys-only.json');
  writeFileSync(file, JSON.stringify(oldFormat(JSON.stringify({ fingerprint, privateKey: b.keys!.privateKey, passphrase: b.keys!.passphrase ?? '' }), FILE_PW, { type: 'svrnty-keys', version: '1.0', fingerprint })));
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
  await page.getByPlaceholder('Encryption password from export').fill(FILE_PW);
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await page.waitForTimeout(8_000);
  console.log(`[restore-honesty] key-only restore, screen after 8 s:\n${(await page.locator('body').innerText()).replace(/\n{2,}/g, '\n')}`);
  await expect(page.getByText(KEY_ONLY_SENTENCE)).toBeVisible({ timeout: 15_000 });
  await ctx.close();
});

test('5. the app\'s own key export (named *.svrnty-keys) is accepted by the picker and opens as a key backup', async ({ browser }, testInfo) => {
  const b = backup as { identity?: { identity?: { fingerprint?: string } }; keys?: { privateKey?: string; passphrase?: string } };
  const fingerprint = b.identity?.identity?.fingerprint;
  const file = testInfo.outputPath(`svrnty-keys-2026-11-14.svrnty-keys`);
  writeFileSync(file, JSON.stringify(oldFormat(JSON.stringify({ fingerprint, privateKey: b.keys!.privateKey, passphrase: b.keys!.passphrase ?? '' }), FILE_PW, { type: 'svrnty-keys', version: '1.0', fingerprint })));
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  // the picker offers the file: its extension is in the accept list
  expect(await page.locator('[data-testid="restore-file-input"]').getAttribute('accept')).toContain('.svrnty-keys');
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
  // opened as a key backup (the password screen), not refused as a vault it cannot read
  await expect(page.getByText(/encrypted key backup detected/i)).toBeVisible({ timeout: 15_000 });
  await ctx.close();
});
