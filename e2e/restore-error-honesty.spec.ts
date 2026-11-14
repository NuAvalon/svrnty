import { test, expect, type Page, type Browser } from '@playwright/test';
import { writeFileSync } from 'node:fs';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { RESTORE_MESSAGES } from '../src/lib/identity/restore-errors';

/**
 * What the restore screen says when a restore fails, through the real screens.
 *
 *  1. An old-format FULL backup (the app's own backup object, encrypted the old way with node:crypto) opens fine but cannot be saved on a fresh device without
 *     a device passphrase. The screen must say THAT, not "Incorrect encryption password": the owner typed the password right.
 *  2. A genuinely WRONG password still says "Incorrect encryption password" (the fix must not over-correct).
 *  3. A file with a password method this version does not read shows its own sentence, not the wrong-password one.
 *
 * Before the fix, 1 and 3 both showed "Incorrect encryption password" (the handler tested the error's TEXT for the words password/passphrase/decrypt).
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
  await page.setInputFiles('input[accept=".svrnty,.json"]', file);
  await page.getByPlaceholder('Encryption password from export').fill(password);
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  const error = page.getByText(/Incorrect encryption password|could not be saved on this device|does not read|could not be restored/i).first();
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

test('1. an old-format full backup that OPENS but cannot be saved on a fresh device says so: it does not say the password was wrong', async ({ browser }, testInfo) => {
  const b = { ...backup! }; delete b.vault;
  const file = testInfo.outputPath('full-old.json');
  writeFileSync(file, JSON.stringify(oldFormat(JSON.stringify(b), FILE_PW, { type: 'svrnty-full-backup', version: '1.0', encrypted: true })));
  const shown = await restoreAndReadError(browser, file, FILE_PW);
  console.log(`[restore-honesty] full backup, RIGHT password: "${shown}"`);
  expect(shown).toBe(RESTORE_MESSAGES.needsDevicePassphrase);
  expect(shown).not.toMatch(/incorrect/i);
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
  expect(shown).toBe('This file uses a password method this version does not read.');
  expect(shown).not.toMatch(/incorrect/i);
});
