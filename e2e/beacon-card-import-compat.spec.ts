import { test, expect, type Page } from '@playwright/test';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard } from '../src/lib/identity/identity-card-sign';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';
import { beaconPublicKey } from '../src/lib/crypto/beacon-key';
import { GENERATION_FLOOR } from '../src/lib/crypto/beacon-generation';

/**
 * #588 T4 compat proof (the T4 note's "UNVERIFIED and must be tested before shipping"): a signed identity card that carries the two NEW
 * identity.* fields (beacon_public_key, beacon_key_generation) must still import through the real copy/paste carrier, as an ordinary verified
 * contact, on whatever client is running. Run it against the OLD client (deployed dev, which has never heard of the fields) AND the new one.
 * If any import step copied the card into a typed struct before verifying, the signature would fail and Bob would see the tampering message.
 * CONTROL: the same card with the beacon key swapped AFTER signing must show the tampering message, so a clean import above cannot be a leftover.
 *
 * The card is built and signed in this process from a throwaway identity; nothing in it is a real secret.
 */
const PASS = 'e2e-passphrase-1234';
const OK = /Contact "Mallory Beacon" added successfully\./;
// A card whose signature fails: branch 3 drops the pq leg, and a canonical (64-hex) fingerprint can't bind without it, so the client refuses it with the
// binding alert (observed on deployed dev); on a card that does import classical-only the message says "possible tampering". Either is a refusal.
const TAMPER = /possible tampering|fingerprint↔key binding failed/i;

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const e = page.getByPlaceholder('your@email.com');
  if (await e.count()) await e.fill('bob@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PASS);
  await page.getByPlaceholder('Confirm passphrase').fill(PASS);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}

async function mallory() {
  const pass = 'pw-mallory';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name: 'Mallory Beacon', email: 'mallory@x.test' }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const key = await beaconPublicKey(BigInt('987654321'));
  const card = await signIdentityCard({
    version: '1.1', type: 'identity-exchange', created_at: new Date().toISOString(),
    identity: {
      fingerprint, display_name: 'Mallory Beacon', public_key: publicKey, email: '',
      pq_sig_public_key: uint8ToBase64(pq.signing.publicKey), pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), next_authority_commitment: '',
      beacon_public_key: key, beacon_key_generation: GENERATION_FLOOR + 1,
    },
  } as any, privateKey, pass);
  return { card, otherKey: await beaconPublicKey(BigInt('123123123')) };
}

async function importText(page: Page, text: string): Promise<string> {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.locator('button:has-text("Import Contact"):not([data-testid="import-contacts-trigger"])').first().click();
  await page.getByPlaceholder('Paste the signed identity package here...').fill(text);
  await page.getByRole('button', { name: /Verify & Import/ }).click();
  const dlg = page.locator('[role="dialog"]').filter({ hasText: /Verify & Import|Import/ }).first();
  await expect(dlg.getByText(/added|updated|could not|invalid|already|tampering|binding failed/i).first()).toBeVisible({ timeout: 30_000 });
  const t = (await dlg.innerText()).replace(/\s+/g, ' ');
  await page.keyboard.press('Escape');
  return t;
}

test('a signed card carrying the beacon fields imports as an ordinary verified contact; a swapped key shows the tampering message', async ({ browser }) => {
  test.setTimeout(240_000);
  const { card, otherKey } = await mallory();
  expect((card.identity as any).beacon_public_key).toBeTruthy();

  const good = await (await browser.newContext()).newPage();
  await genesis(good, 'Bob Good');
  const goodMsg = await importText(good, JSON.stringify(card));
  expect(goodMsg).toMatch(OK);
  expect(goodMsg).not.toMatch(TAMPER);

  // CONTROL: swap the key AFTER signing. The signature covers it, so the importer must object.
  const evil = JSON.parse(JSON.stringify(card));
  evil.identity.beacon_public_key = otherKey;
  const ctl = await (await browser.newContext()).newPage();
  await genesis(ctl, 'Bob Control');
  const evilMsg = await importText(ctl, JSON.stringify(evil));
  expect(evilMsg).toMatch(TAMPER);
  expect(evilMsg).not.toMatch(OK);
  await ctl.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(ctl.locator('[data-testid="contact-row"]').filter({ hasText: 'Mallory Beacon' })).toHaveCount(0);

  // CONTROL 2: strip the fields after signing: also a broken signature.
  const stripped = JSON.parse(JSON.stringify(card));
  delete stripped.identity.beacon_public_key;
  delete stripped.identity.beacon_key_generation;
  const ctl2 = await (await browser.newContext()).newPage();
  await genesis(ctl2, 'Bob Control Two');
  expect(await importText(ctl2, JSON.stringify(stripped))).toMatch(TAMPER);
});
