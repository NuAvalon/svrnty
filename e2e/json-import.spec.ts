import { test, expect, type Browser, type Page } from '@playwright/test';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';

// #765: the JSON contact-book import, driven through the real app. The bug it guards: the import dropped
// pq_kem_public_key / pq_sig_public_key, so every key-bound contact failed its binding and 0 were imported.
// The security rule it keeps: a file carries identity only, so every imported contact lands 'unverified',
// whatever trust the file claims. The store is encrypted at rest, so the test reads what was stored through
// the app's own "Export Contacts as JSON" (which writes trust_level and both post-quantum keys).

const PASS = 'e2e-passphrase-1234';

interface FileContact {
  name: string;
  email: string;
  fingerprint: string;
  public_key: string;
  pq_kem_public_key: string;
  pq_sig_public_key: string;
  trust_level: string;
  [extra: string]: unknown;
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

const book = (contacts: FileContact[]) => JSON.stringify({ contacts, exported_at: '2026-11-13T00:00:00.000Z' }, null, 2);

// Mirrors e2e/import.spec.ts: each new context is an empty IndexedDB, so each identity starts with an empty book.
async function freshIdentity(browser: Browser, name: string): Promise<Page> {
  const page = await (await browser.newContext({ acceptDownloads: true })).newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PASS);
  await page.getByPlaceholder('Confirm passphrase').fill(PASS);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  return page;
}

async function openMore(page: Page) {
  await page.getByRole('button', { name: /^more$/i }).click();
}

/** Pastes the text into Import Contacts from JSON and presses Import. Returns the dialog. */
async function importJson(page: Page, text: string) {
  await openMore(page);
  await page.getByRole('menuitem', { name: /import contacts from json/i }).click();
  const dialog = page.getByRole('dialog', { name: /import contacts/i });
  await expect(dialog).toBeVisible();
  await dialog.getByPlaceholder('Paste contacts JSON here...').fill(text);
  await dialog.getByRole('button', { name: /^import$/i }).click();
  return dialog;
}

/** A clean import (all added, nothing already there, nothing refused) closes the dialog with no message. */
async function importClean(page: Page, text: string, names: string[]) {
  const dialog = await importJson(page, text);
  await expect(dialog).toBeHidden({ timeout: 20_000 });
  for (const n of names) await expect(page.getByText(n, { exact: true }).first()).toBeVisible();
}

/** Export Contacts as JSON through the passphrase gate; returns the parsed file. */
async function exportJson(page: Page): Promise<{ contacts: FileContact[] }> {
  await openMore(page);
  await page.getByRole('menuitem', { name: /export contacts as json/i }).click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(PASS);
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 20_000 }),
    page.getByRole('button', { name: /^continue$/i }).click(),
  ]);
  const path = await download.path();
  const fs = await import('node:fs');
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function byFp(list: FileContact[], fp: string): FileContact {
  const hit = list.find((c) => c.fingerprint === fp);
  expect(hit, `contact ${fp.slice(0, 12)} missing from the export`).toBeTruthy();
  return hit as FileContact;
}

test.describe.configure({ timeout: 180_000 });

test('ROUND TRIP: 2 key-bound contacts import whole, carry both post-quantum keys, arrive unverified; export -> fresh identity -> same; re-import says already in your contacts', async ({ browser }) => {
  const [ann, bob] = [await makeContact('ann-765'), await makeContact('bob-765')];
  const source = book([ann, bob]);

  // Identity A imports the file: both added (the original bug imported 0 here).
  const a = await freshIdentity(browser, 'Alice 765');
  await importClean(a, source, [ann.name, bob.name]);

  // What A stored, read back through the app's own export.
  const fromA = await exportJson(a);
  expect(fromA.contacts).toHaveLength(2);
  for (const src of [ann, bob]) {
    const got = byFp(fromA.contacts, src.fingerprint);
    expect(got.public_key).toBe(src.public_key);
    expect(got.pq_kem_public_key, 'ML-KEM key carried').toBe(src.pq_kem_public_key);
    expect(got.pq_sig_public_key, 'ML-DSA key carried').toBe(src.pq_sig_public_key);
    expect(got.trust_level).toBe('unverified');
  }

  // A fresh identity B imports A's exported file: the export format round-trips.
  const b = await freshIdentity(browser, 'Bea 765');
  await importClean(b, JSON.stringify(fromA), [ann.name, bob.name]);
  const fromB = await exportJson(b);
  expect(fromB.contacts).toHaveLength(2);
  for (const src of [ann, bob]) {
    const got = byFp(fromB.contacts, src.fingerprint);
    expect(got.pq_kem_public_key).toBe(src.pq_kem_public_key);
    expect(got.pq_sig_public_key).toBe(src.pq_sig_public_key);
    expect(got.trust_level).toBe('unverified');
  }

  // Re-import into B: nothing new, and the dialog says so (#422's done-criterion B).
  const again = await importJson(b, source);
  await expect(again.getByText('Added 0, already in your contacts 2.')).toBeVisible({ timeout: 20_000 });
  await again.getByRole('button', { name: /^cancel$/i }).click(); // a note keeps the dialog open
  await expect(again).toBeHidden();
  expect((await exportJson(b)).contacts).toHaveLength(2);
});

// Each crafted contact carries a stamp in one of the three shapes the store's verify-before-trust gate ACCEPTS
// (trust-recipe.ts ownerHasVerified: owner_verify.owner_verified_at, metadata.owner_verify.owner_verified_at, or
// verification{verified_at, method in_person}). So if the import ever took trust_level from the file, the store
// would store these as trusted, and the trust_level assertion below is what catches it (not a store refusal).
// BOUND: this spec reads the store back through Export, which writes a field whitelist, so it cannot see the
// verification STAMPS themselves. An import that spread the entry and then reset trust_level would pass here;
// src/lib/contacts/book-import.test.ts NEG (a)/(b) ("no stamp") pin that layer.
test('NEG: a crafted file that claims trusted, with owner-verify stamps the store would accept, still imports UNVERIFIED', async ({ browser }) => {
  const [mallory, eve, trent] = [await makeContact('mallory-765'), await makeContact('eve-765'), await makeContact('trent-765')];
  const at = '2026-01-01T00:00:00.000Z';
  const crafted = book([
    { ...mallory, trust_level: 'trusted', trusted: true, owner_verify: { owner_verified_at: at } },
    { ...eve, trust_level: 'verified', trusted: true, verification: { status: 'verified', method: 'in_person', verified_at: at } },
    { ...trent, trust_level: 'trusted', trusted: true, metadata: { owner_verify: { owner_verified_at: at } } },
  ]);

  const page = await freshIdentity(browser, 'Carol 765');
  await importClean(page, crafted, [mallory.name, eve.name, trent.name]);

  const stored = await exportJson(page);
  expect(stored.contacts).toHaveLength(3);
  for (const src of [mallory, eve, trent]) {
    const got = byFp(stored.contacts, src.fingerprint);
    expect(got.trust_level, `${src.name}: the file's trust claim is ignored`).toBe('unverified');
    expect(got.pq_kem_public_key).toBe(src.pq_kem_public_key);
  }
});
