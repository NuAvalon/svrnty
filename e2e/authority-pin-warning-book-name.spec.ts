import { test, expect, type Page } from '@playwright/test';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard } from '../src/lib/identity/identity-card-sign';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';

// A card whose authority pin conflicts with the one the owner already holds for that contact must be answered with the BOOK's name for that contact,
// never the card's own display name: a card-supplied string never appears in a security warning. The existing wording spec uses the same name for the book
// entry and the card, so it cannot tell the two apart; here two validly signed cards of ONE identity carry DIFFERENT display names and are pasted into the real
// Import dialog. Real Chromium. This fails on code that passes the card's name to the warning.
const PW = 'e2e-passphrase-1234';
const PIN1 = 'a1'.repeat(32);
const PIN2 = 'b2'.repeat(32);
const BOOK = 'Zedcontact';
const CARD_NAME = 'Mallory Injected';

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
async function nodeIdentity(name: string) {
  const pass = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name.toLowerCase()}@e2e.test` }], passphrase: pass, format: 'armored' } as any);
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase: pass });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const card = (pin: string, display: string) => ({
    version: '1.1', type: 'identity-exchange', created_at: '2026-11-09T00:00:00.000Z',
    identity: { fingerprint, display_name: display, public_key: publicKey, email: `${name.toLowerCase()}@e2e.test`, pq_sig_public_key: uint8ToBase64(pq.signing.publicKey), pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), next_authority_commitment: pin },
  });
  return { signed: async (pin: string, display: string) => JSON.stringify(await signIdentityCard(card(pin, display) as any, privateKey, pass)) };
}
async function paste(page: Page, pkg: string, expectText: RegExp): Promise<string> {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.locator('button:has-text("Import Contact"):not([data-testid="import-contacts-trigger"])').first().click();
  await page.getByPlaceholder('Paste the signed identity package here...').fill(pkg);
  await page.getByRole('button', { name: /Verify & Import/ }).click();
  const dialog = page.locator('[role="dialog"]');
  await expect(dialog.getByText(expectText).first()).toBeVisible({ timeout: 30_000 });
  const text = await dialog.innerText();
  await page.keyboard.press('Escape');
  return text;
}

test('a conflicting authority-pin card is answered with the BOOK contact\'s name, never the card\'s own display name', async ({ browser }) => {
  test.setTimeout(240_000);
  const ctx = await browser.newContext(); const A = await ctx.newPage();
  await genesis(A, 'Alice Probe');
  const zed = await nodeIdentity(BOOK);
  await paste(A, await zed.signed(PIN1, BOOK), /added successfully|added/i);                         // the book now holds "Zedcontact" with pin 1
  const warning = await paste(A, await zed.signed(PIN2, CARD_NAME), /doesn't match the one you already have/i); // a valid card, a DIFFERENT pin, a DIFFERENT display name
    expect(warning, 'control: the warning is the conflict sentence').toMatch(/doesn't match the one you already have/i);
  expect(warning, 'it names the person the owner already holds').toContain(BOOK);
  expect(warning, 'the conflicting card\'s own display name never appears in it').not.toContain(CARD_NAME);
  await ctx.close();
});
