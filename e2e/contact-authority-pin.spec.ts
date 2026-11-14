import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { unpackVault } from '../src/lib/sync/vault';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard } from '../src/lib/identity/identity-card-sign';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';

/**
 * #787 (F0a): a contact's next_authority_commitment (the "pin" a signed card carries) must be RETAINED when the card is imported, so that a
 * later relay move or key rotation can be checked against it. Today no importer stores it, so every contact holds none.
 * Real Chromium, two real identities. The stored contact row is sealed, so the observer is the owner's own vault export, opened in Node.
 * RED on dev by design: the exported contact has no pin.
 */
const PW = 'e2e-passphrase-1234';
const EXPORT_PW = 'export-e2e-pass-5678';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const e = page.getByPlaceholder('your@email.com');
  if (await e.count()) await e.fill(`${name.toLowerCase().replace(/\W+/g, '')}@example.test`);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PW);
  await page.getByPlaceholder('Confirm passphrase').fill(PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}
async function copyPackage(page: Page): Promise<string> {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('share-identity-from-card').click();
  await page.getByRole('tab', { name: 'Copy' }).click();
  const pre = page.locator('[role="dialog"] pre').first();
  await expect(pre).toBeVisible();
  const text = (await pre.innerText()).trim();
  await page.keyboard.press('Escape');
  return text;
}
async function importPackage(page: Page, pkg: string) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.locator('button:has-text("Import Contact"):not([data-testid="import-contacts-trigger"])').first().click();
  await page.getByPlaceholder('Paste the signed identity package here...').fill(pkg);
  await page.getByRole('button', { name: /Verify & Import/ }).click();
  const dlg = page.locator('[role="dialog"]');
  await expect(dlg.getByText(/imported|added|verified|success/i).first()).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press('Escape');
}
async function exportVault(page: Page, dest: string) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const dl = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  await (await dl).saveAs(dest);
  await page.keyboard.press('Escape'); // the "Vault downloaded" dialog stays up and covers the tab bar until it is closed
  await expect(page.getByTestId('vault-export-dialog')).toHaveCount(0, { timeout: 10_000 });
}
/** The pin as the card itself carries it (read off the package text, not from the app's storage). */
function pinOf(pkgText: string): string | null {
  const m = pkgText.match(/"next_authority_commitment"\s*:\s*"([0-9a-f]{64})"/);
  return m ? m[1] : null;
}

test('IMPORT via Contacts: the stored contact retains the card\'s pin (read from the owner\'s own vault export)', async ({ browser }, testInfo) => {
  test.setTimeout(240_000);
  const ctxA = await browser.newContext(); const ctxB = await browser.newContext();
  const A = await ctxA.newPage(); const B = await ctxB.newPage();
  await genesis(A, 'Alice Pin'); await genesis(B, 'Bob Pin');
  const pkgB = await copyPackage(B);
  const pin = pinOf(pkgB);
  expect(pin, 'control: Bob\'s signed package really carries a 64-hex pin').not.toBeNull();
  await importPackage(A, pkgB);
  const dest = testInfo.outputPath('alice.svrnty');
  await exportVault(A, dest);
  const { contents } = await unpackVault(readFileSync(dest).buffer.slice(0) as ArrayBuffer, EXPORT_PW);
  const contacts = ((contents as unknown as { trustGraph: { contacts: Array<Record<string, any>> } }).trustGraph.contacts) ?? [];
  const bob = contacts.find((c) => /bob pin/i.test(String(c.name)));
  expect(bob, 'control: the imported contact is in the export').toBeTruthy();
  console.log(`IMPORT: contact keys = ${Object.keys(bob ?? {}).sort().join(',')} | stored pin = ${bob?.next_authority_commitment ?? '(absent)'} | card pin = ${pin}`);
  expect(bob!.next_authority_commitment, 'the stored contact retains the pin the card carried').toBe(pin);
  await ctxA.close(); await ctxB.close();
});

// ---- first write wins, back-fill, and the loud refusal: three REAL signed cards of ONE identity (built in Node, signed with its key), pasted into the
// real Import dialog: a legacy card with no pin, the same identity with pin 1, then with a DIFFERENT pin 2.
const PIN1 = 'a1'.repeat(32);
const PIN2 = 'b2'.repeat(32);
async function nodeIdentity(name: string) {
  const pass = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name.toLowerCase()}@e2e.test` }], passphrase: pass, format: 'armored' } as any);
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase: pass });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const card = (pin: string) => ({
    version: '1.1', type: 'identity-exchange', created_at: '2026-11-09T00:00:00.000Z',
    identity: { fingerprint, display_name: name, public_key: publicKey, email: `${name.toLowerCase()}@e2e.test`, pq_sig_public_key: uint8ToBase64(pq.signing.publicKey), pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), next_authority_commitment: pin },
  });
  const signed = async (pin: string) => JSON.stringify(await signIdentityCard(card(pin) as any, privateKey, pass));
  return { signed };
}
async function pasteCard(page: Page, pkg: string, expectText: RegExp) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.locator('button:has-text("Import Contact"):not([data-testid="import-contacts-trigger"])').first().click();
  await page.getByPlaceholder('Paste the signed identity package here...').fill(pkg);
  await page.getByRole('button', { name: /Verify & Import/ }).click();
  await expect(page.locator('[role="dialog"]').getByText(expectText).first()).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press('Escape');
}
async function storedPin(page: Page, who: RegExp, testInfo: any, tag: string): Promise<string | undefined> {
  const dest = testInfo.outputPath(`${tag}.svrnty`);
  await exportVault(page, dest);
  const { contents } = await unpackVault(readFileSync(dest).buffer.slice(0) as ArrayBuffer, EXPORT_PW);
  const contacts = ((contents as unknown as { trustGraph: { contacts: Array<Record<string, any>> } }).trustGraph.contacts) ?? [];
  return contacts.find((c) => who.test(String(c.name)))?.next_authority_commitment;
}

test('FIRST WRITE WINS: a legacy card stores no pin; the same identity with a pin BACK-FILLS it; a DIFFERENT pin is refused loudly and changes nothing', async ({ browser }, testInfo) => {
  test.setTimeout(420_000);
  const ctx = await browser.newContext(); const A = await ctx.newPage();
  await genesis(A, 'Alice First');
  const zed = await nodeIdentity('Zedcontact');
  await pasteCard(A, await zed.signed(''), /added successfully|added/i);
  expect(await storedPin(A, /zedcontact/i, testInfo, 'e0'), 'control: a legacy (empty-pin) card stores no pin').toBeUndefined();
  await pasteCard(A, await zed.signed(PIN1), /key material is now stored|updated/i);
  expect(await storedPin(A, /zedcontact/i, testInfo, 'e1'), 'the same identity with a pin back-fills it').toBe(PIN1);
  await pasteCard(A, await zed.signed(PIN2), /doesn't match the one you already have/i);
  expect(await storedPin(A, /zedcontact/i, testInfo, 'e2'), 'a different pin on a valid card leaves the first pin alone').toBe(PIN1);
  await ctx.close();
});
