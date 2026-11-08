import { test, expect, type Browser, type Page } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { packVault, unpackVault } from '../src/lib/sync/vault';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';

// A vault restore tells the owner which contacts it could not bring back.
//
// The store refuses a contact whose fingerprint does not match its keys, and refuses to create a trusted contact with no recorded verification. A restore
// skips those and carries on. The owner must SEE which ones: the note is the proof, and this drives the real screen. (The first version of that note was set
// by the component that shows the gate, which the page REPLACES the moment the identity exists, so the note never reached the screen; a source-text test
// could not see that. This one can.)
//
// Shape: mint an identity (context A) -> export an encrypted vault through the UI -> in Node, add three contacts to the vault (one that restores, one with a
// key that does not match its fingerprint, one marked trusted with no recorded verification) -> restore it in a FRESH context B (a new device) -> the
// owner's screen must carry the note, naming exactly the two that were refused, with the plain reasons.
//
// The note names contacts, so it must not outlive the unlocked session it belongs to: after a lock and unlock it is gone, and after switching to another
// identity on the same device it is gone and none of its names appear.

const APP = 'http://localhost:3000/';
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';

async function mint(page: Page, name = 'Restore Report E2E', pw = UNLOCK_PW, goto = true) {
  if (goto) await page.goto(APP);
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(pw);
  await page.getByPlaceholder('Confirm passphrase').fill(pw);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 45_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

async function exportVault(page: Page, dest: string) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  await (await downloadPromise).saveAs(dest);
}

/** A contact with a real canonical identity (all four keys bound into its fingerprint), as the store's binding check wants. */
async function canonicalContact(name: string) {
  const passphrase = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name.toLowerCase()}@e2e.test` }], passphrase, format: 'armored' });
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return {
    id: `vault-${name}`, owner_fingerprint: 'vault-owner', name, email: `${name.toLowerCase()}@e2e.test`, fingerprint, public_key: publicKey,
    pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey),
    trust_level: 'unverified', added_at: '2026-01-01T00:00:00.000Z',
  };
}

const SENTENCE = '1 of 3 contacts from the backup are on this device.';
const MALLORY = 'Mallory (its key does not match its fingerprint)';
const TRENT = "Trent (it was marked as trusted, but there's no record of verifying it)";

test.describe.configure({ mode: 'serial' });

let vaultPath = '';

/** Mint, export, add three contacts to the vault in Node, and write the result. Built once for the file. */
test.beforeAll(async ({ browser }, testInfo) => {
  testInfo.setTimeout(240_000);
  const ctxA = await browser.newContext();
  const page = await ctxA.newPage();
  await mint(page);
  const exported = testInfo.outputPath('exported.svrnty');
  await exportVault(page, exported);
  await ctxA.close();

  const { contents } = await unpackVault(readFileSync(exported).buffer.slice(0) as ArrayBuffer, EXPORT_PW);
  const dana = await canonicalContact('Dana');                                    // restores
  const trent = { ...(await canonicalContact('Trent')), trust_level: 'trusted' };  // valid binding, trusted with NO recorded verification: refused
  const mallory = { ...(await canonicalContact('Mallory')) };
  mallory.fingerprint = dana.fingerprint.replace(/.$/, dana.fingerprint.endsWith('0') ? '1' : '0'); // a key that does not match its fingerprint: refused
  mallory.public_key = dana.public_key;
  (contents as unknown as { trustGraph: { contacts: unknown[] } }).trustGraph.contacts = [dana, mallory, trent];
  vaultPath = testInfo.outputPath('with-refused-contacts.svrnty');
  writeFileSync(vaultPath, Buffer.from(await packVault(contents, EXPORT_PW)));
});

/** A new device: restore the vault at the gate and land on the owner's screen. */
async function restoreOnNewDevice(browser: Browser) {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  await p.goto(APP);
  await p.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await p.setInputFiles('input[accept=".svrnty,.json"]', vaultPath);
  await p.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
  await p.getByRole('button', { name: /^restore identity$/i }).click();
  await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
  return { ctx, p };
}

async function lockNow(p: Page) {
  await p.getByRole('button', { name: 'Lock now' }).click();
  await expect(p.getByPlaceholder('Enter passphrase')).toBeVisible({ timeout: 15_000 });
}

test('a vault restore shows the owner which contacts it could not restore, and why', async ({ browser }) => {
  test.setTimeout(120_000);
  const { ctx, p } = await restoreOnNewDevice(browser);

  // The screen the owner lands on carries the note.
  const note = p.getByTestId('plaintext-import-note');
  await expect(note).toBeVisible({ timeout: 10_000 });
  await expect(note).toContainText(SENTENCE);
  await expect(note).toContainText(MALLORY);
  await expect(note).toContainText(TRENT);
  await expect(note).not.toContainText('Dana'); // the contact that restored is not listed as refused
  await expect(note).not.toContainText(/restored \d+ of/i); // the old over-claiming wording is gone

  // Dismissing clears it for good.
  await note.getByRole('button').first().click();
  await expect(p.getByTestId('plaintext-import-note')).toHaveCount(0);
  await ctx.close();
});

test('NEG: after a lock and unlock the note is gone (it names contacts of the session that ended)', async ({ browser }) => {
  test.setTimeout(120_000);
  const { ctx, p } = await restoreOnNewDevice(browser);
  await expect(p.getByTestId('plaintext-import-note')).toContainText(SENTENCE);

  await lockNow(p);
  await expect(p.getByText('Mallory')).toHaveCount(0); // nothing of the note on the lock screen either
  await p.getByPlaceholder('Enter passphrase').fill(EXPORT_PW); // a vault restore leaves the vault passphrase as the device passphrase
  await p.getByPlaceholder('Enter passphrase').press('Enter');
  await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });

  await expect(p.getByTestId('plaintext-import-note')).toHaveCount(0);
  await expect(p.getByText('Mallory')).toHaveCount(0);
  await expect(p.getByText('Trent')).toHaveCount(0);
  await ctx.close();
});

test('NEG: switching to another identity on the same device shows no note and none of its names', async ({ browser }) => {
  test.setTimeout(180_000);
  const { ctx, p } = await restoreOnNewDevice(browser);
  await expect(p.getByTestId('plaintext-import-note')).toContainText(SENTENCE);

  await lockNow(p);
  await p.getByRole('button', { name: /\+ new identity/i }).click();
  await mint(p, 'Second Identity E2E', 'second-e2e-pass-3456', false);

  await expect(p.getByTestId('plaintext-import-note')).toHaveCount(0);
  await expect(p.getByText('Mallory')).toHaveCount(0);
  await expect(p.getByText('Trent')).toHaveCount(0);
  await ctx.close();
});
