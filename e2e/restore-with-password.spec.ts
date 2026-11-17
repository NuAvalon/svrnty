import { test, expect, type Page, type BrowserContext, type Browser } from '@playwright/test';
import { writeFileSync } from 'node:fs';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { RESTORE_MESSAGES } from '../src/lib/identity/restore-errors';

/**
 * A full backup restored on a device with no session yet, through the real screens, checked against the real IndexedDB.
 *  a. right password (>= 12) on a fresh device: restored, and the device now unlocks with that password (the screen says so)
 *  b. wrong password: the wrong-password sentence, and NOTHING is written (no salt row, no owner rows)
 *  c. a forged fingerprint: refused before any write
 *  d. the device already holds the owner under another passphrase: refused, nothing changed
 *  e. the device holds the owner and the file password is that passphrase: restored
 *  e2. a MIXED device (keys under A, a vault under B): refused under either passphrase, nothing changed
 *  g. a weak (8-char) file password only OPENS the file: the screen asks for a new device password first (nothing written), the new one unlocks the device, the weak one does not
 *  h. a plain backup (no password of its own) asks for a device password the same way
 *  f. a restore that stops after ANY write and is run again with the same file ends in the same state as a clean restore (incl. contacts, block both ways)
 * Needs a PRODUCTION build served on PLAYWRIGHT_BASE_URL. The harness needs the page script policy off (bypassCSP).
 */
const UNLOCK_PW = 'unlock-e2e-pass-1234';   // the owner's device passphrase on the minting device
const FILE_PW = 'restore-e2e-pass-5678';    // >= 12
const OTHER_PW = 'another-e2e-pass-9012';   // >= 12, not the device's
const WEAK_PW = 'short-pw';                 // 8 characters
const NEW_DEVICE_PW = 'chosen-device-pass-3456';
test.setTimeout(900_000);
test.describe.configure({ mode: 'serial' });

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
const HARNESS = bundle('e2e/helpers/restore-harness.ts');

type Backup = { identity: { identity: { fingerprint: string; public_key: string; name?: string }; post_quantum?: Record<string, string> }; keys: { privateKey: string; passphrase: string }; contacts: Array<Record<string, unknown>>; [k: string]: unknown };
const rh = <T = any>(page: Page, fn: string, ...args: unknown[]): Promise<T> => page.evaluate(([f, a]) => (window as any).__rh[f as string](...(a as unknown[])), [fn, args] as [string, unknown[]]) as Promise<T>;

async function newPage(browser: Browser, inject = true): Promise<{ ctx: BrowserContext; page: Page }> {
  const ctx = await browser.newContext({ bypassCSP: true });
  const page = await ctx.newPage();
  await page.addInitScript(() => {
    const target = ['identities', 'keys', 'pq_keys', 'vaults', 'shards', 'device_mailbox', 'contacts'];
    (window as any).__puts = 0;
    for (const m of ['put', 'add'] as const) {
      const orig = (IDBObjectStore.prototype as any)[m];
      (IDBObjectStore.prototype as any)[m] = function (this: IDBObjectStore, ...a: unknown[]) {
        if (target.includes(this.name)) {
          (window as any).__puts++;
          let at = 0, from = 0; try { at = Number(sessionStorage.getItem('failAt') || 0); from = Number(sessionStorage.getItem('failFrom') || 0); } catch { /* none */ }
          if (at && (window as any).__puts === at) throw new DOMException('injected failure', 'AbortError');
          if (from && (window as any).__puts >= from) throw new DOMException('injected failure', 'AbortError'); // every write from the Nth on: a write that retries still fails
        }
        return orig.apply(this, a);
      };
    }
  });
  await page.goto('/');
  if (inject) await page.addScriptTag({ content: HARNESS });
  return { ctx, page };
}

async function mint(page: Page, name: string) {
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 60_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}

const idbFirstIdentity = (page: Page) => page.evaluate(() => new Promise<string | null>((resolve) => {
  const open = indexedDB.open('svrnty');
  open.onerror = () => resolve(null);
  open.onsuccess = () => { const db = open.result; const r = db.transaction('identities').objectStore('identities').getAllKeys(); r.onsuccess = () => { db.close(); resolve((r.result[0] as string) ?? null); }; r.onerror = () => { db.close(); resolve(null); }; };
}));

/** Rows per owner store, and whether this browser has a device-key salt yet. Reads only. */
const deviceState = (page: Page) => page.evaluate(() => new Promise<Record<string, number | boolean>>((resolve) => {
  const open = indexedDB.open('svrnty');
  open.onerror = () => resolve({});
  open.onsuccess = () => {
    const db = open.result; const out: Record<string, number | boolean> = {};
    const stores = ['identities', 'keys', 'pq_keys', 'vaults', 'shards', 'device_mailbox', 'contacts'].filter((s) => db.objectStoreNames.contains(s));
    const tx = db.transaction([...stores, 'settings'], 'readonly');
    for (const s of stores) { const c = tx.objectStore(s).count(); c.onsuccess = () => { out[s] = c.result; }; }
    const salt = tx.objectStore('settings').get('key_encryption_salt'); salt.onsuccess = () => { out.salt = !!salt.result; };
    tx.oncomplete = () => { db.close(); resolve(out); };
  };
}));
/** Is there a row under this key in the settings store? Reads only. */
const hasSetting = (page: Page, key: string) => page.evaluate((k) => new Promise<boolean>((resolve) => {
  const open = indexedDB.open('svrnty');
  open.onerror = () => resolve(false);
  open.onsuccess = () => { const db = open.result; const r = db.transaction('settings').objectStore('settings').get(k); r.onsuccess = () => { db.close(); resolve(r.result !== undefined); }; };
}), key);
/** The settings rows that belong to this owner (by key), sorted. Reads only. */
const ownerSettingKeys = (page: Page, fpr: string) => page.evaluate((f) => new Promise<string[]>((resolve) => {
  const open = indexedDB.open('svrnty');
  open.onerror = () => resolve([]);
  open.onsuccess = () => { const db = open.result; const r = db.transaction('settings').objectStore('settings').getAllKeys(); r.onsuccess = () => { db.close(); resolve((r.result as string[]).filter((k) => String(k).includes(f)).map(String).sort()); }; };
}), fpr);
/** The pieces row for this owner exactly as stored (ciphertext and all), or the string "null". Reads only. */
const rawShardsRecord = (page: Page, fp: string) => page.evaluate((f) => new Promise<string>((resolve) => {
  const open = indexedDB.open('svrnty');
  open.onsuccess = () => { const db = open.result; const r = db.transaction('shards').objectStore('shards').get(f); r.onsuccess = () => { db.close(); resolve(JSON.stringify(r.result ?? null)); }; };
}), fp);
const rawKeyRecord = (page: Page, fp: string) => page.evaluate((f) => new Promise<string>((resolve) => {
  const open = indexedDB.open('svrnty');
  open.onsuccess = () => { const db = open.result; const r = db.transaction('keys').objectStore('keys').get(f); r.onsuccess = () => { db.close(); resolve(JSON.stringify(r.result ?? null)); }; };
}), fp);

/** An envelope in the OLD format built with node:crypto only (PBKDF2-SHA256 100k + AES-256-GCM): the file's password check is real. */
function envelope(plain: string, password: string) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, 100_000, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plain)), c.final(), c.getAuthTag()]);
  return { type: 'svrnty-full-backup', version: '1.0', encrypted: true, algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA256-100k', salt: salt.toString('base64'), iv: iv.toString('base64'), data: ct.toString('base64') };
}

async function openRestoreScreen(page: Page, file: string) {
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
}
const PROMPT = (p: Page) => p.getByTestId('device-password-prompt');
const ERROR_RE = /didn't open this file|This device already has this identity|has no password yet|can't read|can't be read|isn't a backup|Something went wrong|stopped partway|stopped before any of your data was saved|may have been saved/i;
/** After pressing the restore button: wait for the first thing that settles the attempt. */
async function settle(page: Page): Promise<'restored' | 'prompt' | 'error'> {
  const restored = page.getByRole('tab', { name: 'Contacts', exact: true });
  const err = page.getByText(ERROR_RE).first();
  const first = await Promise.race([
    restored.waitFor({ timeout: 90_000 }).then(() => 'restored' as const),
    PROMPT(page).waitFor({ timeout: 90_000 }).then(() => 'prompt' as const),
    err.waitFor({ timeout: 90_000 }).then(() => 'error' as const),
  ]);
  return first;
}
async function restoreWith(page: Page, file: string, password: string) {
  await openRestoreScreen(page, file);
  await page.getByPlaceholder('Encryption password from export').fill(password);
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  return settle(page);
}

let backup: Backup;
let fp: string;
const clean = (obj: unknown) => JSON.parse(JSON.stringify(obj));

test.beforeAll(async ({ browser }) => {
  // owner B: a second identity, only to give the backup one real KEYED contact (a fingerprint that binds to its keys)
  const b = await newPage(browser);
  await mint(b.page, 'Keyed Contact B');
  const bFp = (await idbFirstIdentity(b.page))!;
  const bBackup = (await rh<Backup>(b.page, 'all', bFp, UNLOCK_PW));
  await b.ctx.close();
  const bi = bBackup.identity.identity;
  // owner A: the backup under test, with contacts (two identical keyless rows, one keyless row blocked via metadata, one keyed)
  const a = await newPage(browser);
  await mint(a.page, 'Restore With Password E2E');
  fp = (await idbFirstIdentity(a.page))!;
  await rh(a.page, 'addContacts', fp, UNLOCK_PW, [
    { name: 'Same Name', email: 'same@example.test', public_key: '', fingerprint: '', trust_level: 'known' },
    { name: 'Same Name', email: 'same@example.test', public_key: '', fingerprint: '', trust_level: 'known' },
    { name: 'Blocked Keyless', email: 'blocked@example.test', public_key: '', fingerprint: '', trust_level: 'known', metadata: { blocked: true } },
    { name: bi.name ?? 'Keyed B', email: '', public_key: bi.public_key, fingerprint: bi.fingerprint, pq_kem_public_key: bBackup.identity.post_quantum?.kem_public_key, pq_sig_public_key: bBackup.identity.post_quantum?.sig_public_key, trust_level: 'known' },
  ]);
  backup = clean(await rh<Backup>(a.page, 'all', fp, UNLOCK_PW));
  expect(backup.identity.identity.fingerprint).toBe(fp);
  expect(backup.keys?.privateKey, 'the backup carries the key').toBeTruthy();
  expect(backup.contacts.length, 'the backup carries the four contacts').toBe(4);
  await a.ctx.close();
});

const writeFull = (testInfo: { outputPath: (n: string) => string }, name: string, b: unknown, pw: string) => {
  const file = testInfo.outputPath(name);
  writeFileSync(file, JSON.stringify(envelope(JSON.stringify(b), pw)));
  return file;
};
const noVault = () => { const b = { ...backup } as Record<string, unknown>; delete b.vault; return b; };

test('a. right password (>= 12) on a fresh device: restored, durable, and the screen says the device now unlocks with that password', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  const file = writeFull(testInfo, 'full.json', noVault(), FILE_PW);
  expect(await restoreWith(page, file, FILE_PW)).toBe('restored');
  await expect(page.getByTestId('plaintext-import-note')).toContainText(RESTORE_MESSAGES.deviceUsesFilePassword);
  await expect(page.getByTestId('plaintext-import-note')).toContainText(/4 landed Known/);
  const st = await deviceState(page);
  console.log('[restore-pw] a. device state:', JSON.stringify(st));
  expect(st.salt).toBe(true); expect(st.keys).toBe(1); expect(st.contacts).toBe(4);
  await page.reload(); await page.addScriptTag({ content: HARNESS });
  expect(await rh(page, 'verify', fp, FILE_PW), 'the file password now unlocks the device (read back from the key row)').toBe(true);
  await ctx.close();
});

test('b. wrong password: the wrong-password sentence, nothing written', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  const file = writeFull(testInfo, 'full-b.json', noVault(), FILE_PW);
  expect(await restoreWith(page, file, 'definitely-the-wrong-pass')).toBe('error');
  await expect(page.getByText(RESTORE_MESSAGES.wrongPassword)).toBeVisible();
  const st = await deviceState(page);
  console.log('[restore-pw] b. device state:', JSON.stringify(st));
  expect(st.salt).toBeFalsy(); expect(st.keys).toBe(0); expect(st.identities).toBe(0);
  await ctx.close();
});

test('c. a forged fingerprint is refused before any write', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  const forged = clean(noVault()) as Backup;
  forged.identity.identity.fingerprint = 'f'.repeat(64);
  const file = writeFull(testInfo, 'full-c.json', forged, FILE_PW);
  expect(await restoreWith(page, file, FILE_PW)).toBe('error');
  const st = await deviceState(page);
  console.log('[restore-pw] c. device state:', JSON.stringify(st));
  expect(st.salt).toBeFalsy(); expect(st.keys).toBe(0); expect(st.identities).toBe(0); expect(st.contacts).toBe(0);
  await ctx.close();
});

test('d. the device already holds the owner under another passphrase: refused, nothing changed', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seed', fp, backup.keys, UNLOCK_PW);
  await page.reload();
  const before = await rawKeyRecord(page, fp);
  const stBefore = await deviceState(page);
  const file = writeFull(testInfo, 'full-d.json', noVault(), OTHER_PW);
  expect(await restoreWith(page, file, OTHER_PW)).toBe('error');
  await expect(page.getByText(/This device already has this identity/)).toBeVisible();
  await expect(page.getByText(/Your current profile is left as it is\./)).toBeVisible();
  expect(await rawKeyRecord(page, fp)).toBe(before);
  const st = await deviceState(page);
  console.log('[restore-pw] d. before/after:', JSON.stringify(stBefore), JSON.stringify(st));
  expect(st).toEqual(stBefore);
  await ctx.close();
});

test('e. the device holds the owner and the file password IS its passphrase: restored', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seed', fp, backup.keys, UNLOCK_PW);
  await page.reload();
  const file = writeFull(testInfo, 'full-e.json', noVault(), UNLOCK_PW);
  expect(await restoreWith(page, file, UNLOCK_PW)).toBe('restored');
  const st = await deviceState(page);
  expect(st.contacts).toBe(4);
  await ctx.close();
});

test('e2. a MIXED device (keys under A, a vault under B) refuses a restore under either passphrase, and nothing changes', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seed', fp, backup.keys, UNLOCK_PW, OTHER_PW);
  await page.reload();
  const stBefore = await deviceState(page);
  for (const pw of [UNLOCK_PW, OTHER_PW]) {
    const file = writeFull(testInfo, `full-e2-${pw.slice(0, 4)}.json`, noVault(), pw);
    await page.reload();
    expect(await restoreWith(page, file, pw), `restore under ${pw.slice(0, 4)}…`).toBe('error');
    await expect(page.getByText(/This device already has this identity/)).toBeVisible();
    await expect(page.getByText(/Your current profile is left as it is\./)).toBeVisible();
    expect(await deviceState(page)).toEqual(stBefore);
  }
  await ctx.close();
});

test('j. a MIXED device (key under A, a contact under B) refuses a restore under either passphrase, and nothing changes', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seedKeyAndContact', fp, backup.keys, UNLOCK_PW, OTHER_PW, { name: 'Held Under Other', email: 'other@example.test', public_key: '', fingerprint: '', trust_level: 'known' });
  await page.reload();
  const stBefore = await deviceState(page);
  expect(stBefore.contacts, 'the seeded contact row is on the device').toBe(1);
  for (const pw of [UNLOCK_PW, OTHER_PW]) {
    const file = writeFull(testInfo, `full-j-${pw.slice(0, 4)}.json`, noVault(), pw);
    await page.reload();
    expect(await restoreWith(page, file, pw), `restore under ${pw.slice(0, 4)}…`).toBe('error');
    await expect(page.getByText(/This device already has this identity/)).toBeVisible();
    await expect(page.getByText(/Your current profile is left as it is\./)).toBeVisible();
    expect(await deviceState(page)).toEqual(stBefore);
  }
  await ctx.close();
});

test('k. a device that ALREADY held the owner, failing at the first write, says nothing was saved (not "part of it was saved"), and the same file then restores', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seed', fp, backup.keys, UNLOCK_PW);
  await page.reload();
  await page.evaluate(() => sessionStorage.setItem('failAt', '1'));
  const stBefore = await deviceState(page);
  const file = writeFull(testInfo, 'full-k.json', noVault(), UNLOCK_PW);
  expect(await restoreWith(page, file, UNLOCK_PW)).toBe('error');
  await expect(page.getByText(RESTORE_MESSAGES.stoppedNothingSaved)).toBeVisible();
  await expect(page.getByText(RESTORE_MESSAGES.stoppedPartway)).toHaveCount(0);
  expect(await deviceState(page), 'the device really is unchanged').toEqual(stBefore);
  await page.evaluate(() => sessionStorage.removeItem('failAt'));
  await page.reload(); await page.addScriptTag({ content: HARNESS });
  expect(await restoreWith(page, file, UNLOCK_PW), 're-run with the same file').toBe('restored');
  await ctx.close();
});

test('l. a device whose receipts default is under another passphrase than its key and contact refuses a restore under either passphrase, and nothing changes', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seedKeyContactDelivery', fp, backup.keys, UNLOCK_PW, OTHER_PW, { name: 'Held Under Key', email: 'held@example.test', public_key: '', fingerprint: '', trust_level: 'known' });
  await page.reload();
  const stBefore = await deviceState(page);
  expect(stBefore.contacts, 'the seeded contact row is on the device').toBe(1);
  for (const pw of [UNLOCK_PW, OTHER_PW]) {
    const file = writeFull(testInfo, `full-l-${pw.slice(0, 4)}.json`, noVault(), pw);
    await page.reload();
    expect(await restoreWith(page, file, pw), `restore under ${pw.slice(0, 4)}…`).toBe('error');
    await expect(page.getByText(/This device already has this identity/)).toBeVisible();
    await expect(page.getByText(/Your current profile is left as it is\./)).toBeVisible();
    expect(await deviceState(page)).toEqual(stBefore);
  }
  await ctx.close();
});

test('n. a device with NO contacts whose receipts default is under another passphrase than its key refuses a restore under either passphrase, and nothing changes', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seedKeyContactDelivery', fp, backup.keys, UNLOCK_PW, OTHER_PW, null);
  await page.reload();
  const stBefore = await deviceState(page);
  expect(stBefore.contacts, 'there is no contact row, so the receipts default alone puts the device in two passphrase domains').toBe(0);
  expect(await hasSetting(page, `delivery_receipts:${fp}`)).toBe(true);
  for (const pw of [UNLOCK_PW, OTHER_PW]) {
    const file = writeFull(testInfo, `full-n-${pw.slice(0, 4)}.json`, noVault(), pw);
    await page.reload();
    expect(await restoreWith(page, file, pw), `restore under ${pw.slice(0, 4)}…`).toBe('error');
    await expect(page.getByText(/This device already has this identity/)).toBeVisible();
    expect(await deviceState(page)).toEqual(stBefore);
  }
  await ctx.close();
});

// Every owner-sealed settings record other than the receipts default (cases l, n, m): held ALONE under one passphrase beside the key under another, a restore under either is refused.
for (const sealed of ['suppression', 'held-affirms', 'lens-book', 'beacon-seeds', 'beacon-key']) {
  test(`o. owner-sealed record "${sealed}" under another passphrase than the key: a restore under either passphrase is refused, and nothing changes`, async ({ browser }, testInfo) => {
    const { ctx, page } = await newPage(browser);
    await rh(page, 'seedKeyAndSealed', fp, backup.keys, UNLOCK_PW, OTHER_PW, sealed);
    await page.reload();
    const keysBefore = await ownerSettingKeys(page, fp);
    expect(keysBefore.length, `the ${sealed} record is on the device`).toBeGreaterThanOrEqual(1);
    const stBefore = await deviceState(page);
    expect(stBefore.contacts, 'no contact row: the sealed record alone makes the two domains').toBe(0);
    for (const pw of [UNLOCK_PW, OTHER_PW]) {
      const file = writeFull(testInfo, `full-o-${sealed}-${pw.slice(0, 4)}.json`, noVault(), pw);
      await page.reload();
      expect(await restoreWith(page, file, pw), `${sealed}: restore under ${pw.slice(0, 4)}…`).toBe('error');
      await expect(page.getByText(/This device already has this identity/)).toBeVisible();
      expect(await deviceState(page)).toEqual(stBefore);
      expect(await ownerSettingKeys(page, fp), 'no settings row was written or removed').toEqual(keysBefore);
    }
    await ctx.close();
  });
}

test('m. a device that already holds the owner but has no receipts default: a failure AFTER the default is written reads as part saved, never as "before any of your data was saved"', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  expect(backup.device_mailbox, 'the backup carries the device mailbox').toBeTruthy();
  await rh(page, 'seedHeldFull', fp, backup.keys, backup.identity, backup.device_mailbox, UNLOCK_PW);
  await page.reload();
  // Every owner-store write from the 2nd on fails, found by running this restore with the failure starting at each write: the identity row (write 1, an identical rewrite) succeeds,
  // the receipts default (a settings write the counter does not see) is written, and the key write (write 2) fails. The device already holds its mailbox, so the unlock step has nothing
  // to heal and the receipts default is the ONLY difference. (The key write retries, so a single numbered failure would be absorbed.)
  await page.evaluate(() => sessionStorage.setItem('failFrom', '2'));
  const keyBefore = await rawKeyRecord(page, fp);
  const receiptsBefore = await hasSetting(page, `delivery_receipts:${fp}`);
  expect(receiptsBefore, 'the seeded device has no receipts default').toBe(false);
  const file = writeFull(testInfo, 'full-m.json', noVault(), UNLOCK_PW);
  expect(await restoreWith(page, file, UNLOCK_PW)).toBe('error');
  expect(await hasSetting(page, `delivery_receipts:${fp}`), 'the restore wrote the receipts default before it failed').toBe(true);
  console.log(`[restore-pw] m. the screen says: "${(await page.getByText(ERROR_RE).first().innerText()).trim()}"`);
  await expect(page.getByText(RESTORE_MESSAGES.stoppedNothingSaved), 'the receipts default WAS saved, so the screen must not say nothing was').toHaveCount(0);
  await expect(page.getByText(RESTORE_MESSAGES.stoppedPartway)).toBeVisible();
  expect(await rawKeyRecord(page, fp), 'the key row is untouched (the failure was at the key write)').toBe(keyBefore);
  await page.evaluate(() => sessionStorage.removeItem('failFrom'));
  await page.reload(); await page.addScriptTag({ content: HARNESS });
  expect(await restoreWith(page, file, UNLOCK_PW), 're-run with the same file').toBe('restored');
  await ctx.close();
});

test('g. a weak (8-char) file password only OPENS the file: a new device password is asked for first, and it is the one that unlocks', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  const file = writeFull(testInfo, 'full-g.json', noVault(), WEAK_PW);
  expect(await restoreWith(page, file, WEAK_PW)).toBe('prompt');
  await expect(PROMPT(page)).toContainText(RESTORE_MESSAGES.chooseDevicePasswordWeakFile);
  const st1 = await deviceState(page);
  console.log('[restore-pw] g. while the prompt is up:', JSON.stringify(st1));
  expect(st1.salt).toBeFalsy(); expect(st1.keys).toBe(0); expect(st1.identities).toBe(0);
  // back out: nothing was saved, and the screen says so
  await PROMPT(page).getByRole('button', { name: /^back$/i }).click();
  await expect(page.getByText(RESTORE_MESSAGES.nothingSavedYet)).toBeVisible();
  // again, and choose a password
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await expect(PROMPT(page)).toBeVisible({ timeout: 60_000 });
  await PROMPT(page).getByPlaceholder('New device password').fill(NEW_DEVICE_PW);
  await PROMPT(page).getByPlaceholder('Confirm device password').fill(NEW_DEVICE_PW);
  await PROMPT(page).getByRole('button', { name: /save to this device/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 90_000 });
  await expect(page.getByTestId('plaintext-import-note')).not.toContainText(RESTORE_MESSAGES.deviceUsesFilePassword);
  await page.reload(); await page.addScriptTag({ content: HARNESS });
  expect(await rh(page, 'verify', fp, NEW_DEVICE_PW), 'the new device password unlocks').toBe(true);
  expect(await rh(page, 'verify', fp, WEAK_PW), 'the 8-char file password does NOT').toBe(false);
  await ctx.close();
});

test('h. a plain backup (no password of its own) asks for a device password the same way', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  const file = testInfo.outputPath('plain.json');
  writeFileSync(file, JSON.stringify(noVault()));
  await openRestoreScreen(page, file);
  await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await expect(PROMPT(page)).toContainText(RESTORE_MESSAGES.chooseDevicePasswordNoFilePassword, { timeout: 60_000 });
  expect((await deviceState(page)).salt).toBeFalsy();
  await PROMPT(page).getByPlaceholder('New device password').fill(NEW_DEVICE_PW);
  await PROMPT(page).getByPlaceholder('Confirm device password').fill(NEW_DEVICE_PW);
  await PROMPT(page).getByRole('button', { name: /save to this device/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 90_000 });
  await ctx.close();
});

test('i. contacts the device already holds are kept, never copied; a block in the backup is SET on the existing row (both flag places); a block here is never cleared', async ({ browser }, testInfo) => {
  const { ctx, page } = await newPage(browser);
  await rh(page, 'seed', fp, backup.keys, UNLOCK_PW);
  // the device already holds: "Blocked Keyless" UNBLOCKED, and one "Same Name" BLOCKED in both places
  await rh(page, 'addContacts', fp, UNLOCK_PW, [
    { name: 'Blocked Keyless', email: 'blocked@example.test', public_key: '', fingerprint: '', trust_level: 'known' },
    { name: 'Same Name', email: 'same@example.test', public_key: '', fingerprint: '', trust_level: 'known', blocked: true, metadata: { blocked: true } },
  ]);
  await page.reload(); await page.addScriptTag({ content: HARNESS });
  const file = writeFull(testInfo, 'full-i.json', noVault(), UNLOCK_PW);
  expect(await restoreWith(page, file, UNLOCK_PW)).toBe('restored');
  const note = page.getByTestId('plaintext-import-note');
  await expect(note).toContainText('2 contacts were already on this device and were kept as they are, apart from the blocks below.');
  await expect(note).toContainText('1 contact blocked in your backup is now blocked on this device too.');
  await page.reload(); await page.addScriptTag({ content: HARNESS });
  const snap = clean(await rh(page, 'snapshot', fp, UNLOCK_PW));
  const named = (n: string) => snap.contacts.filter((c: any) => c.name === n);
  console.log('[restore-pw] i. contacts after:', JSON.stringify(snap.contacts.map((c: any) => [c.name, c.blocked, c.metaBlocked])));
  expect(snap.contacts.length, 'no copies: 2 kept + 2 added').toBe(4);
  expect(named('Blocked Keyless')).toHaveLength(1);
  expect(named('Blocked Keyless')[0]).toMatchObject({ blocked: true, metaBlocked: true });
  expect(named('Same Name')).toHaveLength(2);
  expect(named('Same Name').filter((c: any) => c.blocked && c.metaBlocked), 'the block that was here is still there, and was not copied onto the new row').toHaveLength(1);
  await ctx.close();
});

test('f. a restore that stops after ANY write, run again with the same file, ends where a clean restore ends', async ({ browser }, testInfo) => {
  const file = writeFull(testInfo, 'full-f.json', noVault(), FILE_PW);
  // the clean run: how many writes there are, and the state to match
  const clean1 = await newPage(browser);
  expect(await restoreWith(clean1.page, file, FILE_PW)).toBe('restored');
  const writes: number = await clean1.page.evaluate(() => (window as any).__puts);
  await clean1.page.reload(); await clean1.page.addScriptTag({ content: HARNESS });
  const reference = clean(await rh(clean1.page, 'snapshot', fp, FILE_PW));
  await clean1.ctx.close();
  console.log(`[restore-pw] f. clean restore = ${writes} owner-store writes; contacts ${reference.contacts.length}`);
  expect(writes).toBeGreaterThanOrEqual(6);
  expect(reference.contacts.length).toBe(4);
  expect(reference.contacts.find((c: any) => c.name === 'Blocked Keyless')).toMatchObject({ blocked: true, metaBlocked: true });
  const results: string[] = [];
  for (let n = 1; n <= writes; n++) {
    const { ctx, page } = await newPage(browser);
    await page.evaluate((k) => sessionStorage.setItem('failAt', String(k)), n);
    await openRestoreScreen(page, file);
    await page.getByPlaceholder('Encryption password from export').fill(FILE_PW);
    await page.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
    const first = await settle(page);
    const partial = await deviceState(page);
    // EVERY stop is a failed restore (never "restored"): identity, keys, pq keys, shards, device mailbox, and each of the four contacts.
    expect(first, `a stop at write ${n} must not read as restored`).toBe('error');
    // and the screen says what the device holds by COMPARING it with its state before the first write: write 1 died before any owner row (nothing saved);
    // from write 2 on, part of it is saved
    if (n === 1) {
      await expect(page.getByText(RESTORE_MESSAGES.stoppedNothingSaved)).toBeVisible();
      await expect(page.getByText(RESTORE_MESSAGES.stoppedPartway)).toHaveCount(0);
    } else {
      await expect(page.getByText(RESTORE_MESSAGES.stoppedPartway)).toBeVisible();
      await expect(page.getByText(RESTORE_MESSAGES.stoppedNothingSaved)).toHaveCount(0);
    }
    // run it again: same file, no failure injected, a fresh page (the session is gone)
    await page.evaluate(() => sessionStorage.removeItem('failAt'));
    await page.reload(); await page.addScriptTag({ content: HARNESS });
    const gate = page.getByRole('button', { name: /restore your identity from a vault file/i });
    const reachable = await gate.waitFor({ timeout: 8_000 }).then(() => true).catch(() => false);
    if (!reachable) { results.push(`${n}:${first}:rerun-NOT-REACHABLE`); console.log(`[restore-pw] f. stop at write ${n}/${writes}: ${first}; partial=${JSON.stringify(partial)}; the restore screen is NOT reachable from this state`); await ctx.close(); continue; }
    expect(await restoreWith(page, file, FILE_PW), `re-run after a stop at write ${n}`).toBe('restored');
    await expect(page.getByTestId('plaintext-import-note')).not.toContainText(/skipped/);
    // contacts written before the stop are reported as already on the device (a stop at write 7 left one, 8 two, 9 three); none were left before that
    if (n >= 7) await expect(page.getByTestId('plaintext-import-note')).toContainText(/already on this device/);
    else await expect(page.getByTestId('plaintext-import-note')).not.toContainText(/already on this device/);
    await page.reload(); await page.addScriptTag({ content: HARNESS });
    const after = clean(await rh(page, 'snapshot', fp, FILE_PW));
    results.push(`${n}:${first}:rerun-ok`);
    console.log(`[restore-pw] f. stop at write ${n}/${writes}: ${first}; partial=${JSON.stringify(partial)} -> contacts ${after.contacts.length}`);
    expect(after, `state after stop at write ${n} + re-run equals a clean restore`).toEqual(reference);
    await ctx.close();
  }
  console.log(`[restore-pw] f. summary: ${results.join(' | ')}`);
});

test('p. a recovery-pieces record that is not a usable set is left out and the rest of the backup restores, and the screen says so; a usable record restores and stores it', async ({ browser }, testInfo) => {
  const piece = (i: number, t: number, o: Record<string, unknown> = {}) => ({ index: i + 1, data: 'AAAA', identity_fingerprint: fp, threshold: t, ...o });
  const withShards = (shards: unknown): Record<string, unknown> => { const b = clean(noVault()) as Record<string, unknown>; b.shards = shards; return b; };
  const set = (threshold: number, total: number, n: number, edit: (p: Record<string, unknown>, i: number) => Record<string, unknown> = (x) => x) => ({ threshold, total, shards: Array.from({ length: n }, (_, i) => edit(piece(i, threshold), i)) });
  const bad: Array<[string, unknown]> = [
    ['a threshold of 1 (the give-a-piece screen would print "Any 1 of your keepers ... no single piece can")', set(1, 2, 2)],
    ['a piece that names another identity', set(3, 5, 5, (x, i) => (i === 2 ? { ...x, identity_fingerprint: 'f'.repeat(64) } : x))],
    ['two pieces with the same index', set(3, 5, 5, (x, i) => (i === 3 ? { ...x, index: 1 } : x))],
  ];
  for (const [name, shards] of bad) {
    const { ctx, page } = await newPage(browser);
    expect(await restoreWith(page, writeFull(testInfo, 'full-p-bad.json', withShards(shards), FILE_PW), FILE_PW), `${name}: the rest of the backup restores`).toBe('restored');
    await expect(page.getByTestId('plaintext-import-note'), `${name}: the screen says the record was not restored`).toContainText(RESTORE_MESSAGES.piecesRecordNotRestored);
    const st = await deviceState(page);
    console.log(`[restore-pw] p. left out (${name}), device state:`, JSON.stringify(st));
    expect(st.identities, name).toBe(1); expect(st.keys, name).toBe(1); expect(st.contacts, name).toBe(4); expect(st.salt, name).toBe(true);
    expect(st.shards, `${name}: nothing was stored as the pieces record`).toBe(0);
    await ctx.close();
  }
  // the control: the same backup with a usable 3-of-5 record restores, stores it, and says nothing about pieces
  const ok = await newPage(browser);
  expect(await restoreWith(ok.page, writeFull(testInfo, 'full-p-ok.json', withShards(set(3, 5, 5)), FILE_PW), FILE_PW)).toBe('restored');
  await expect(ok.page.getByTestId('plaintext-import-note')).not.toContainText(RESTORE_MESSAGES.piecesRecordNotRestored);
  const stored = await deviceState(ok.page);
  console.log('[restore-pw] p. control restored, device state:', JSON.stringify(stored));
  expect(stored.keys).toBe(1); expect(stored.shards).toBe(1);
  await ok.ctx.close();
});

test('q. a damaged pieces record in the backup, restored onto a device that already holds a good one: the device\'s record is kept byte for byte and the screen says nothing about pieces; with no record of its own the same restore says so', async ({ browser }, testInfo) => {
  const piece = (i: number, t: number) => ({ index: i + 1, data: 'AAAA', identity_fingerprint: fp, threshold: t });
  const set = (threshold: number, total: number, n: number) => ({ threshold, total, shards: Array.from({ length: n }, (_, i) => piece(i, threshold)) });
  const damaged = (): Record<string, unknown> => { const b = clean(noVault()) as Record<string, unknown>; b.shards = set(1, 2, 2); return b; }; // a threshold of 1: not a usable set
  const file = writeFull(testInfo, 'full-q.json', damaged(), UNLOCK_PW);
  // the device already holds the owner AND its own good 3-of-5 record
  const held = await newPage(browser);
  await rh(held.page, 'seedKeyAndShards', fp, backup.keys, UNLOCK_PW, set(3, 5, 5));
  await held.page.reload(); await held.page.addScriptTag({ content: HARNESS });
  const before = await rawShardsRecord(held.page, fp);
  expect(before, 'the device holds its own pieces record before the restore').not.toBe('null');
  expect(await restoreWith(held.page, file, UNLOCK_PW)).toBe('restored');
  const note = held.page.getByTestId('plaintext-import-note');
  await expect(note, 'the restore note is on screen').toBeVisible();
  await expect(note, 'a good record is already here: nothing is said about pieces').not.toContainText(RESTORE_MESSAGES.piecesRecordNotRestored);
  await expect(held.page.getByText(RESTORE_MESSAGES.piecesRecordNotRestored), 'and the sentence is nowhere on the screen').toHaveCount(0);
  const after = await rawShardsRecord(held.page, fp);
  console.log(`[restore-pw] q. held device: pieces row before ${before.length} chars, after ${after.length} chars, identical ${after === before}`);
  expect(after, 'the device\'s own record is byte for byte what it was (not rewritten, not dropped)').toBe(before);
  const st = await deviceState(held.page);
  expect(st.shards, 'one pieces row, the device\'s own').toBe(1); expect(st.keys).toBe(1); expect(st.contacts, 'the rest of the backup restored').toBe(4);
  await held.ctx.close();
  // the control: the device holds the owner's key but NO pieces record: the same file now says so, and stores none
  const bare = await newPage(browser);
  await rh(bare.page, 'seedKeyAndShards', fp, backup.keys, UNLOCK_PW);
  await bare.page.reload(); await bare.page.addScriptTag({ content: HARNESS });
  expect(await rawShardsRecord(bare.page, fp)).toBe('null');
  expect(await restoreWith(bare.page, file, UNLOCK_PW)).toBe('restored');
  await expect(bare.page.getByTestId('plaintext-import-note'), 'no record of its own: the sentence is shown').toContainText(RESTORE_MESSAGES.piecesRecordNotRestored);
  const stBare = await deviceState(bare.page);
  expect(stBare.shards, 'nothing was stored as the pieces record').toBe(0); expect(stBare.contacts).toBe(4);
  await bare.ctx.close();
});
