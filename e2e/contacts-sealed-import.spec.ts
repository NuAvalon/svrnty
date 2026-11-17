import { test, expect, type Browser, type Page } from '@playwright/test';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { RESTORE_MESSAGES } from '../src/lib/identity/restore-errors';
import { SEALED_BOOK_MESSAGES } from '../src/lib/contacts/sealed-book-import';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

// The password-protected "Export Contacts" file (identity card menu) has to come back in. Before this change no screen read it: pasted into the contact
// book's "Import Contacts from JSON" it ended at "No contacts found in that file.", because the file is a sealed envelope and the importer only reads plain JSON.
// The real export is driven through the app (identity card menu -> unlock passphrase -> export password), and the real import through the contact book.
// The data-testid values are the contract with the screen; the sentences are not asserted here except the existing wrong-password one.

const UNLOCK_PW = 'e2e-passphrase-1234';
const EXPORT_PW = 'contacts-export-pass-77';   // >= 12
const WRONG_PW = 'definitely-the-wrong-pass';

test.describe.configure({ timeout: 240_000 });

interface FileContact {
  name: string; email: string; fingerprint: string; public_key: string;
  pq_kem_public_key: string; pq_sig_public_key: string; trust_level: string;
}

/** A real contact: an ed25519 key, a post-quantum bundle, and the canonical fingerprint over all three. */
async function makeContact(name: string): Promise<FileContact> {
  const passphrase = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name}@t.test` }], passphrase, format: 'armored' });
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return {
    name, email: `${name}@t.test`, fingerprint, public_key: publicKey,
    pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey),
    trust_level: 'unverified',
  };
}
const book = (contacts: FileContact[]) => JSON.stringify({ contacts, exported_at: '2026-11-15T00:00:00.000Z' }, null, 2);

async function freshIdentity(browser: Browser, name: string): Promise<Page> {
  const page = await (await browser.newContext({ acceptDownloads: true })).newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  return page;
}

async function openImport(page: Page) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.getByRole('button', { name: /^more$/i }).click();
  await page.getByRole('menuitem', { name: /import contacts from json/i }).click();
  const dialog = page.getByRole('dialog', { name: /import contacts/i });
  await expect(dialog).toBeVisible();
  return dialog;
}

/** Paste plain JSON and import it (how a contact gets into identity A's book). */
async function importPlain(page: Page, text: string, names: string[]) {
  const dialog = await openImport(page);
  await dialog.getByPlaceholder('Paste contacts JSON here...').fill(text);
  await dialog.getByRole('button', { name: /^import$/i }).click();
  await expect(dialog).toBeHidden({ timeout: 20_000 });
  for (const n of names) await expect(page.getByText(n, { exact: true }).first()).toBeVisible();
}

/** The REAL sealed export: identity card menu -> unlock passphrase -> export password. Returns the file's text. */
async function sealedExport(page: Page, opts: { includeKeys: boolean } = { includeKeys: true }): Promise<string> {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByText('Export Contacts', { exact: true }).click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  const dialog = page.getByRole('dialog', { name: /export contacts/i });
  await expect(dialog).toBeVisible({ timeout: 30_000 });
  if (!opts.includeKeys) await dialog.getByLabel(/include public keys/i).uncheck();
  // The field is found by its LABEL (its accessible name), not by its placeholder: placeholders are copy that gets reworded. The short visible-wait makes a
  // stale locator fail in seconds with a readable error instead of waiting out the whole test timeout.
  const exportPw = dialog.getByLabel('Export password (required)', { exact: true });
  await expect(exportPw).toBeVisible({ timeout: 10_000 });
  await exportPw.fill(EXPORT_PW);
  await dialog.getByRole('button', { name: /^export contacts$/i }).click();
  const area = dialog.locator('textarea[readonly]');
  await expect(area).toBeVisible({ timeout: 120_000 });
  const text = await area.inputValue();
  await dialog.getByRole('button', { name: /^close$/i }).last().click();
  return text;
}

/** A source identity holding two real contacts, and the sealed file it exports. */
async function sourceFile(browser: Browser, opts?: { includeKeys: boolean }): Promise<{ file: string; names: string[]; fps: string[] }> {
  const [ann, bob] = [await makeContact('ann-837'), await makeContact('bob-837')];
  const a = await freshIdentity(browser, 'Alice 837');
  await importPlain(a, book([ann, bob]), [ann.name, bob.name]);
  const file = await sealedExport(a, opts);
  await a.context().close();
  return { file, names: [ann.name, bob.name], fps: [ann.fingerprint, bob.fingerprint] };
}

const passwordField = (dialog: ReturnType<Page['getByRole']>) => dialog.getByTestId('contacts-import-password');

/** The first identity's fingerprint in this browser's IndexedDB. Reads only. */
const myFingerprint = (page: Page) => page.evaluate(() => new Promise<string | null>((resolve) => {
  const open = indexedDB.open('svrnty');
  open.onerror = () => resolve(null);
  open.onsuccess = () => { const db = open.result; const r = db.transaction('identities').objectStore('identities').getAllKeys(); r.onsuccess = () => { db.close(); resolve((r.result[0] as string) ?? null); }; };
}));

/** A sealed file in the OLDER format, built with node:crypto only (PBKDF2-SHA256 100k + AES-256-GCM). The app still reads it; it lets a test craft any plaintext. */
function legacySealed(plain: string, password: string): string {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, 100_000, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plain)), c.final(), c.getAuthTag()]);
  return JSON.stringify({ encrypted: true, algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA256-100k', salt: salt.toString('base64'), iv: iv.toString('base64'), data: ct.toString('base64') });
}

/** The plain "Export Contacts as JSON" (More menu): what the book now holds, with the trust each contact landed at. */
async function plainExport(page: Page): Promise<{ contacts: FileContact[] }> {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.getByRole('button', { name: /^more$/i }).click();
  await page.getByRole('menuitem', { name: /export contacts as json/i }).click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 20_000 }),
    page.getByRole('button', { name: /^continue$/i }).click(),
  ]);
  return JSON.parse(readFileSync(await download.path(), 'utf8'));
}

/** Paste a sealed file, give the password, press Import. Returns the dialog (it stays open when there is a note or an error). */
async function importSealed(page: Page, file: string, password: string) {
  const dialog = await openImport(page);
  await dialog.getByPlaceholder('Paste contacts JSON here...').fill(file);
  await expect(dialog.getByTestId('contacts-import-password')).toBeVisible({ timeout: 5_000 });
  await dialog.getByTestId('contacts-import-password').fill(password);
  await dialog.getByRole('button', { name: /^import$/i }).click();
  return dialog;
}


test('1. the real sealed export, pasted into Import Contacts on ANOTHER identity, asks for its password, imports every contact (unverified), and says once that another identity exported them', async ({ browser }) => {
  const { file, names } = await sourceFile(browser);
  expect(JSON.parse(file).encrypted, 'the export really is a sealed envelope').toBe(true);

  const b = await freshIdentity(browser, 'Bea 837');
  const dialog = await openImport(b);
  await dialog.getByPlaceholder('Paste contacts JSON here...').fill(file);
  await expect(passwordField(dialog), 'the dialog asks for the export password').toBeVisible({ timeout: 5_000 });
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.passwordLabel)).toBeVisible();
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.alwaysUnverified)).toBeVisible();
  await passwordField(dialog).fill(EXPORT_PW);
  await dialog.getByRole('button', { name: /^import$/i }).click();
  // another identity exported it: a fixed notice, and the dialog stays open to show it
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.differentOwner)).toBeVisible({ timeout: 60_000 });
  await dialog.getByRole('button', { name: /^cancel$/i }).click();
  await b.getByRole('tab', { name: 'Contacts', exact: true }).click();
  for (const n of names) await expect(b.getByText(n, { exact: true }).first()).toBeVisible();
  const stored = await plainExport(b);
  expect(stored.contacts.map((c) => c.trust_level), 'every imported contact is unverified').toEqual(['unverified', 'unverified']);
  await b.context().close();
});

test('2. a wrong password says so, in the existing wrong-password sentence, and adds nothing', async ({ browser }) => {
  const { file, names } = await sourceFile(browser);
  const b = await freshIdentity(browser, 'Bea 837b');
  const dialog = await importSealed(b, file, WRONG_PW);
  await expect(dialog.getByText(RESTORE_MESSAGES.wrongPassword)).toBeVisible({ timeout: 60_000 });
  await dialog.getByRole('button', { name: /^cancel$/i }).click();
  for (const n of names) await expect(b.getByText(n, { exact: true })).toHaveCount(0);
  await b.context().close();
});

test('3. importing the same sealed file again adds nothing twice', async ({ browser }) => {
  const { file, names } = await sourceFile(browser);
  const b = await freshIdentity(browser, 'Bea 837c');
  const first = await importSealed(b, file, EXPORT_PW);
  await expect(first.getByText(SEALED_BOOK_MESSAGES.differentOwner)).toBeVisible({ timeout: 60_000 });
  await first.getByRole('button', { name: /^cancel$/i }).click();
  const again = await importSealed(b, file, EXPORT_PW);
  await expect(again.getByText(/Added 0, already in your contacts 2\./)).toBeVisible({ timeout: 60_000 });
  await again.getByRole('button', { name: /^cancel$/i }).click();
  for (const n of names) await expect(b.getByText(n, { exact: true })).toHaveCount(1);
  await b.context().close();
});

test('4. a sealed export made WITHOUT public keys opens; every row is refused with the fixed missing-keys sentence (a count, no names); nothing is added', async ({ browser }) => {
  const { file, names } = await sourceFile(browser, { includeKeys: false });
  const b = await freshIdentity(browser, 'Bea 837d');
  const dialog = await importSealed(b, file, EXPORT_PW);
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.missingKeys(2))).toBeVisible({ timeout: 60_000 });
  await expect(dialog.getByText(names[0])).toHaveCount(0);
  await dialog.getByRole('button', { name: /^cancel$/i }).click();
  for (const n of names) await expect(b.getByText(n, { exact: true })).toHaveCount(0);
  await b.context().close();
});

test('5. the SAME identity importing its own sealed export: nothing new, and NO different-identity notice (a match says nothing and changes nothing)', async ({ browser }) => {
  const [ann, bob] = [await makeContact('ann-837m'), await makeContact('bob-837m')];
  const a = await freshIdentity(browser, 'Alice 837m');
  await importPlain(a, book([ann, bob]), [ann.name, bob.name]);
  const file = await sealedExport(a);
  const dialog = await importSealed(a, file, EXPORT_PW);
  await expect(dialog.getByText(/Added 0, already in your contacts 2\./)).toBeVisible({ timeout: 60_000 });
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.differentOwner)).toHaveCount(0);
  await dialog.getByRole('button', { name: /^cancel$/i }).click();
  const stored = await plainExport(a);
  expect(stored.contacts).toHaveLength(2);
  await a.context().close();
});

test('6. NEG: a sealed file claiming THIS identity as its owner, whose rows claim trusted (with owner-verify stamps), lands every row UNVERIFIED and shows no notice', async ({ browser }) => {
  const [mallory, eve] = [await makeContact('mallory-837'), await makeContact('eve-837')];
  const page = await freshIdentity(browser, 'Carol 837');
  const mine = (await myFingerprint(page))!;
  const at = '2026-01-01T00:00:00.000Z';
  const plain = JSON.stringify({
    version: '1.0', owner_fingerprint: mine,
    contacts: [
      { ...mallory, trust_level: 'trusted', trusted: true, owner_verify: { owner_verified_at: at } },
      { ...eve, trust_level: 'verified', trusted: true, verification: { status: 'verified', method: 'in_person', verified_at: at } },
    ],
  });
  const dialog = await importSealed(page, legacySealed(plain, EXPORT_PW), EXPORT_PW);
  await expect(dialog).toBeHidden({ timeout: 60_000 }); // a clean import with no notice closes the dialog
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  for (const n of [mallory.name, eve.name]) await expect(page.getByText(n, { exact: true }).first()).toBeVisible();
  const stored = await plainExport(page);
  expect(stored.contacts).toHaveLength(2);
  for (const c of stored.contacts) expect(c.trust_level, `${c.name}: the file's trust claim is ignored`).toBe('unverified');
  await page.context().close();
});

test('7. a sealed file this app cannot read (a method it will not run) says it cannot read it, never "wrong password", and adds nothing', async ({ browser }) => {
  const { file, names } = await sourceFile(browser);
  const unreadable = JSON.stringify({ ...JSON.parse(file), kdf: 'scrypt-n14' });
  const b = await freshIdentity(browser, 'Bea 837e');
  const dialog = await importSealed(b, unreadable, EXPORT_PW);
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.malformed)).toBeVisible({ timeout: 60_000 });
  await expect(dialog.getByText(RESTORE_MESSAGES.wrongPassword)).toHaveCount(0);
  await dialog.getByRole('button', { name: /^cancel$/i }).click();
  for (const n of names) await expect(b.getByText(n, { exact: true })).toHaveCount(0);
  await b.context().close();
});

test('8. a sealed file exported BEFORE the post-quantum keys were written (canonical fingerprints, no post-quantum keys): every row gets the missing-keys sentence, not "key does not match"; nothing is added', async ({ browser }) => {
  const [ann, bob] = [await makeContact('ann-837o'), await makeContact('bob-837o')];
  const old = [ann, bob].map(({ name, email, fingerprint, public_key, trust_level }) => ({ name, email, fingerprint, public_key, trust_level }));
  const plain = JSON.stringify({ version: '1.0', owner_fingerprint: 'e'.repeat(64), contacts: old });
  const b = await freshIdentity(browser, 'Bea 837f');
  const dialog = await importSealed(b, legacySealed(plain, EXPORT_PW), EXPORT_PW);
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.missingKeys(2))).toBeVisible({ timeout: 60_000 });
  await expect(dialog.getByText(/does not match its fingerprint/i)).toHaveCount(0);
  await dialog.getByRole('button', { name: /^cancel$/i }).click();
  for (const n of [ann.name, bob.name]) await expect(b.getByText(n, { exact: true })).toHaveCount(0);
  await b.context().close();
});

test('9. REMOVING an imported, unverified contact sends nothing: no request of any kind leaves the page, and the contact is gone from the book', async ({ browser }) => {
  const { file, names } = await sourceFile(browser);
  const b = await freshIdentity(browser, 'Bea 837g');
  const dialog = await importSealed(b, file, EXPORT_PW);
  await expect(dialog.getByText(SEALED_BOOK_MESSAGES.differentOwner)).toBeVisible({ timeout: 60_000 });
  await dialog.getByRole('button', { name: /^cancel$/i }).click();
  await b.getByRole('tab', { name: 'Contacts', exact: true }).click();
  const row = b.locator('[data-testid="contact-row"]').filter({ hasText: names[0] });
  await expect(row).toBeVisible();

  // CONTROL first: what the page asks of the network on its own over an idle window (the app polls the relay queue on a timer, removal or not)
  const idle: string[] = [];
  const onIdle = (r: import('@playwright/test').Request) => idle.push(`${r.method()} ${new URL(r.url()).pathname}`);
  b.on('request', onIdle);
  await b.waitForTimeout(6_000);
  b.off('request', onIdle);
  console.log(`[sealed-remove] idle window (control): ${JSON.stringify([...new Set(idle)])}`);

  // everything the page asks of the network from the first click to a few seconds after the removal
  const requests: string[] = [];
  b.on('request', (r) => requests.push(`${r.method()} ${new URL(r.url()).pathname}`));
  await row.click();
  await b.getByRole('button', { name: /^actions$/i }).click();
  await b.getByRole('menuitem', { name: /remove/i }).click();
  const confirm = b.getByTestId('trust-action-confirm');
  await expect(confirm).toBeVisible();
  await confirm.getByTestId('trust-action-confirm-btn').click();
  await expect(confirm).toHaveCount(0);
  await expect(b.locator('[data-testid="contact-row"]').filter({ hasText: names[0] })).toHaveCount(0);
  await b.waitForTimeout(4_000); // a fire-and-forget request would be issued by now
  console.log(`[sealed-remove] requests during the removal: ${JSON.stringify([...new Set(requests)])}`);
  expect(requests.filter((r) => !r.startsWith('GET ')), 'no write of any kind').toEqual([]);
  const routine = new Set(idle);
  expect([...new Set(requests)].filter((r) => /\/api\//.test(r) && !routine.has(r)), 'nothing to the relay or the satellite that the idle page does not already do').toEqual([]);
  await b.context().close();
});
