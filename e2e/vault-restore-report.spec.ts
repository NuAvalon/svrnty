import { test, expect, type Page } from '@playwright/test';
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

const APP = 'http://localhost:3000/';
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';

async function mint(page: Page) {
  await page.goto(APP);
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Restore Report E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
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

test('a vault restore shows the owner which contacts it could not restore, and why', async ({ page, browser }, testInfo) => {
  test.setTimeout(240_000);

  await mint(page);
  const exported = testInfo.outputPath('exported.svrnty');
  await exportVault(page, exported);

  // Rebuild the vault with three contacts the restore will treat differently.
  const { contents } = await unpackVault(readFileSync(exported).buffer.slice(0) as ArrayBuffer, EXPORT_PW);
  const dana = await canonicalContact('Dana');                                  // restores
  const trent = { ...(await canonicalContact('Trent')), trust_level: 'trusted' }; // valid binding, trusted with NO recorded verification: refused
  const mallory = { ...(await canonicalContact('Mallory')) };
  mallory.fingerprint = dana.fingerprint.replace(/.$/, dana.fingerprint.endsWith('0') ? '1' : '0'); // a key that does not match its fingerprint: refused
  mallory.public_key = dana.public_key;
  (contents as unknown as { trustGraph: { contacts: unknown[] } }).trustGraph.contacts = [dana, mallory, trent];
  const vaultPath = testInfo.outputPath('with-refused-contacts.svrnty');
  writeFileSync(vaultPath, Buffer.from(await packVault(contents, EXPORT_PW)));

  // A new device.
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  await p.goto(APP);
  await p.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await p.setInputFiles('input[accept=".svrnty,.json"]', vaultPath);
  await p.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
  await p.getByRole('button', { name: /^restore identity$/i }).click();
  await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });

  // The screen the owner lands on carries the note.
  const note = p.getByTestId('plaintext-import-note');
  await expect(note).toBeVisible({ timeout: 10_000 });
  await expect(note).toContainText('1 of 3 contacts from the backup are on this device.');
  await expect(note).toContainText("Mallory (its key does not match its fingerprint)");
  await expect(note).toContainText("Trent (it was marked as trusted, but there's no record of verifying it)");
  await expect(note).not.toContainText('Dana'); // the contact that restored is not listed as refused
  await expect(note).not.toContainText(/restored \d+ of/i); // the old over-claiming wording is gone

  // Dismissing clears it for good (it is not re-shown by the page's copy).
  await note.getByRole('button').first().click();
  await expect(p.getByTestId('plaintext-import-note')).toHaveCount(0);

  await ctx.close();
});
