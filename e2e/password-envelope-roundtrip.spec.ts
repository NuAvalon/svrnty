import { test, expect, type Page, type Browser } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { openWithPassword } from '../src/lib/crypto/password-envelope';

/**
 * The password envelope, through the real screens, in both formats.
 *
 *  A. NEW: "Download Keys" writes an Argon2id file (header checked, no trace of the older method), and restoring it on a fresh device stores the key.
 *  B. OLD key file: a file in the format the app used to write (built here with node:crypto, which shares no code with the app: PBKDF2-SHA256, 100,000
 *     iterations, AES-256-GCM) still restores and stores the key. The unchanged build was run on the same file: it stores the key too, so the file is a
 *     faithful old-format file.
 *  C. A wrong password stores nothing.
 *  D. The key export asks for 12 characters on screen (label, and the button is disabled below 12).
 *
 * NOT driven in a browser, and why (all existing behaviour, reported separately, each checked against the unchanged build where it says so):
 *  - the "export a new copy" notice after an old-format restore. The two old-format restore paths that exist cannot show it today: a key-only restore at the
 *    gate stores the key and shows nothing (there is no identity record to land on), and the old full-backup restore fails on a fresh device with "Incorrect
 *    encryption password" in the UNCHANGED build too (same file, same message). The notice is set on both paths in code; its text is unit-tested.
 *  - the contacts export/import dialogs: SecureImportDialog is not mounted anywhere (nothing imports it), so no screen reaches it.
 *  - the gate only reads a file as JSON when its NAME ends in .json or .svrnty, and Download Keys names its file *.svrnty-keys; this spec restores a copy
 *    named .json.
 *
 * "The key is in IndexedDB" is the observable result of a key-only restore, since no screen reports one. Needs a PRODUCTION build (`next build && next start`).
 */

const UNLOCK_PW = 'unlock-e2e-pass-1234';
const KEY_PW = 'key-file-e2e-pass-5678';

test.setTimeout(240_000);
test.describe.configure({ mode: 'serial' });

async function mint(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Envelope E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 60_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}

async function openKeyExportDialog(page: Page) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByText('Download Keys', { exact: true }).click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByPlaceholder('Enter a strong password')).toBeVisible();
}

async function downloadKeys(page: Page, dest: string) {
  await openKeyExportDialog(page);
  await page.getByPlaceholder('Enter a strong password').fill(KEY_PW);
  await page.getByPlaceholder('Confirm your password').fill(KEY_PW);
  const download = page.waitForEvent('download', { timeout: 180_000 });
  await page.getByRole('button', { name: /download encrypted key/i }).click();
  await (await download).saveAs(dest);
}

/**
 * The restore picker (handleFileSelect) reads a file as JSON only when its NAME ends in .json or .svrnty, and the picker's accept list is ".svrnty,.json";
 * Download Keys names its file *.svrnty-keys, which the picker then rejects ("Not a valid .svrnty vault file"). That is existing behaviour, separate from
 * the password envelope, and is reported on its own; here the file is restored under a .json name, as a user would have to rename it.
 */
function asJson(file: string): string {
  const copy = file.replace(/\.svrnty-keys$/, '.json');
  writeFileSync(copy, readFileSync(file));
  return copy;
}

/** A fresh device: pick the key file at the gate and enter its password. Returns the page, un-submitted. */
async function openRestore(browser: Browser, file: string, password: string) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', asJson(file));
  await page.getByPlaceholder('Encryption password from export').fill(password);
  return { ctx, page };
}

/** An envelope in the OLD format, built with node:crypto only (nothing from the app): PBKDF2-SHA256, 100,000 iterations, AES-256-GCM. */
function oldFormat(plain: string, password: string, extra: Record<string, unknown>) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, 100_000, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plain)), c.final(), c.getAuthTag()]);
  return { ...extra, algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA256-100k', salt: salt.toString('base64'), iv: iv.toString('base64'), data: ct.toString('base64') };
}

/** Is a private key stored for this fingerprint in the app's own IndexedDB? (What a key-only restore leaves; there is no screen for it.) */
async function keyStored(page: Page, fingerprint: string): Promise<boolean> {
  return page.evaluate((fp) => new Promise<boolean>((resolve) => {
    const open = indexedDB.open('svrnty');
    open.onerror = () => resolve(false);
    open.onsuccess = () => {
      const db = open.result;
      try {
        const get = db.transaction('keys').objectStore('keys').get(fp);
        get.onsuccess = () => { db.close(); resolve(!!get.result); };
        get.onerror = () => { db.close(); resolve(false); };
      } catch { db.close(); resolve(false); }
    };
  }), fingerprint);
}

let newFile = '';
let payload: { fingerprint: string; privateKey: string; passphrase: string; pq_keys?: unknown } | null = null;

test('A. Download Keys writes an Argon2id file, and restoring it on a new device stores the key', async ({ browser }, testInfo) => {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  await mint(page);
  newFile = testInfo.outputPath('keys-new.svrnty-keys');
  await downloadKeys(page, newFile);

  const raw = readFileSync(newFile, 'utf8');
  const env = JSON.parse(raw);
  expect(env.type).toBe('svrnty-keys');
  expect(env.kdf).toBe('argon2id');
  expect(env.kdf_params).toEqual({ time_cost: 3, memory_cost: 65536, parallelism: 1 });
  expect(Buffer.from(env.salt, 'base64')).toHaveLength(16);
  expect(raw, 'no trace of the older method in the file').not.toMatch(/PBKDF2/i);
  const opened = await openWithPassword(env, KEY_PW);
  expect(opened.legacy).toBe(false);
  payload = JSON.parse(new TextDecoder().decode(opened.plaintext));
  expect(payload!.fingerprint).toBe(env.fingerprint);
  expect(payload!.privateKey).toContain('BEGIN PGP PRIVATE KEY');

  await ctx.close();

  const { ctx: c2, page: p2 } = await openRestore(browser, newFile, KEY_PW);
  expect(await keyStored(p2, payload!.fingerprint), 'nothing stored before the restore').toBe(false);
  await p2.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await expect.poll(() => keyStored(p2, payload!.fingerprint), { timeout: 120_000, message: 'the Argon2id key file opened and its key was stored' }).toBe(true);
  await c2.close();
});

test('B. a key file in the OLD format (made outside the app) still restores: its key is stored', async ({ browser }, testInfo) => {
  expect(payload, 'test A ran').not.toBeNull();
  const oldFile = testInfo.outputPath('keys-old.svrnty-keys');
  writeFileSync(oldFile, JSON.stringify(oldFormat(JSON.stringify(payload), KEY_PW, { version: '1.0', type: 'svrnty-keys', fingerprint: payload!.fingerprint }), null, 2));
  const { ctx, page } = await openRestore(browser, oldFile, KEY_PW);
  expect(await keyStored(page, payload!.fingerprint), 'nothing stored before the restore').toBe(false);
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await expect.poll(() => keyStored(page, payload!.fingerprint), { timeout: 120_000, message: 'the old-format key file opened and its key was stored' }).toBe(true);
  await ctx.close();
});

test('C. a wrong password stores nothing and leaves the restore screen as it was', async ({ browser }) => {
  expect(newFile).not.toBe('');
  const { ctx, page } = await openRestore(browser, newFile, 'not-the-password-123');
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await page.waitForTimeout(20_000); // an Argon2id attempt takes seconds; give a wrong-password failure time to show
  expect(await keyStored(page, payload!.fingerprint), 'a wrong password stores no key').toBe(false);
  await expect(page.getByPlaceholder('Encryption password from export')).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).not.toBeVisible();
  await ctx.close();
});

test('D. the key export asks for 12 characters on screen: the label says so, and the button stays disabled until the password is 12', async ({ browser }) => {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  await mint(page);
  await openKeyExportDialog(page);
  await expect(page.getByText('Password (minimum 12 characters)')).toBeVisible();
  const button = page.getByRole('button', { name: /download encrypted key/i });
  for (const [pw, enabled] of [['x'.repeat(8), false], ['x'.repeat(11), false], ['x'.repeat(12), true]] as const) {
    await page.getByPlaceholder('Enter a strong password').fill(pw);
    await page.getByPlaceholder('Confirm your password').fill(pw);
    if (enabled) await expect(button).toBeEnabled(); else await expect(button).toBeDisabled();
  }
  await ctx.close();
});
