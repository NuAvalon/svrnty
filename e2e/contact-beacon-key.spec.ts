import { test, expect, type Page, type TestInfo } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { unpackVault } from '../src/lib/sync/vault';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard } from '../src/lib/identity/identity-card-sign';
import type { IdentityCard } from '../src/lib/format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../src/lib/identity/fingerprint';
import { beaconPublicKey } from '../src/lib/crypto/beacon-key';
import { GENERATION_FLOOR } from '../src/lib/crypto/beacon-generation';

/**
 * A contact's beacon key (mutual-trust wire, dark): a signed card that carries one is stored on the contact, first-write-wins, and the sentences the person
 * sees are the right ones. Real Chromium, one real identity importing cards built in Node and signed with their own key (the app's own card builder never
 * carries a beacon key yet). The stored contact row is sealed, so the observer is the owner's own vault export, opened in Node.
 * NOT covered here: an unreadable OWN beacon key (it needs a planted unreadable row); that rule is pinned in the unit tests.
 */
const PW = 'e2e-passphrase-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
const G = (n: number) => GENERATION_FLOOR + n;

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

async function nodeIdentity(name: string) {
  const pass = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name.toLowerCase()}@e2e.test` }], passphrase: pass, format: 'armored' });
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase: pass });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const card = (beacon?: { key: string; gen: number }, displayName?: string) => ({
    version: '1.1', type: 'identity-exchange', created_at: '2026-11-09T00:00:00.000Z',
    identity: {
      fingerprint, display_name: displayName ?? name, public_key: publicKey, email: `${name.toLowerCase()}@e2e.test`,
      pq_sig_public_key: uint8ToBase64(pq.signing.publicKey), pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), next_authority_commitment: '',
      ...(beacon ? { beacon_public_key: beacon.key, beacon_key_generation: beacon.gen } : {}),
    },
  });
  const signed = async (beacon?: { key: string; gen: number }, displayName?: string) => JSON.stringify(await signIdentityCard(card(beacon, displayName) as unknown as IdentityCard, privateKey, pass));
  return { signed };
}
async function pasteCard(page: Page, pkg: string, expectText: RegExp, forbid?: RegExp) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.locator('button:has-text("Import Contact"):not([data-testid="import-contacts-trigger"])').first().click();
  await page.getByPlaceholder('Paste the signed identity package here...').fill(pkg);
  await page.getByRole('button', { name: /Verify & Import/ }).click();
  await expect(page.locator('[role="dialog"]').getByText(expectText).first()).toBeVisible({ timeout: 30_000 });
  // the RESULT line only: the dialog's textarea still holds the pasted card, whose own name is exactly what must NOT appear in the sentence
  if (forbid) await expect(page.locator('[role="dialog"] [role="alert"]')).not.toContainText(forbid);
  await page.keyboard.press('Escape');
}
async function storedBeacon(page: Page, who: RegExp, testInfo: TestInfo, tag: string): Promise<{ key?: string; gen?: number }> {
  const dest = testInfo.outputPath(`${tag}.svrnty`);
  await exportVault(page, dest);
  const { contents } = await unpackVault(readFileSync(dest).buffer.slice(0) as ArrayBuffer, EXPORT_PW);
  const contacts = ((contents as unknown as { trustGraph: { contacts: Array<Record<string, unknown>> } }).trustGraph.contacts) ?? [];
  const c = contacts.find((x) => who.test(String(x.name)));
  expect(c, `control: the contact ${who} is in the export`).toBeTruthy();
  return { key: c!.beacon_public_key as string | undefined, gen: c!.beacon_key_generation as number | undefined };
}

// The sentence for a same-generation DIFFERENT key: it names the EXISTING contact (from the person's own book), never the name the card carries.
const CONFLICT = /A card for "Zedcontact" doesn't match a key you already have for them, so it wasn't applied\./;

test('BEACON KEY: a legacy card stores none; the same identity with one BACK-FILLS it; a repeat changes nothing; a DIFFERENT key at the same generation is refused loudly; a HIGHER generation REPLACES the key, release-first, and says so in the reviewed words; a NEW contact gets the key at add', async ({ browser }, testInfo) => {
  test.skip(!!process.env.E2E_PROD, 'needs WebAssembly (the curve check): a production build refuses it, see the next case');
  test.setTimeout(480_000);
  const KEY_A = await beaconPublicKey(BigInt('111111'));
  const KEY_B = await beaconPublicKey(BigInt('222222'));
  const ctx = await browser.newContext(); const A = await ctx.newPage();
  await genesis(A, 'Alice Beacon');
  const zed = await nodeIdentity('Zedcontact');
  await pasteCard(A, await zed.signed(), /added successfully|added/i);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'e0'), 'control: a legacy card (no beacon key) stores none').toEqual({ key: undefined, gen: undefined });
  await pasteCard(A, await zed.signed({ key: KEY_A, gen: G(3) }), /key material is now stored|updated/i);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'e1'), 'the same identity with a beacon key back-fills it, with its generation').toEqual({ key: KEY_A, gen: G(3) });
  await pasteCard(A, await zed.signed({ key: KEY_A, gen: G(3) }), /already have/i);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'e2'), 'the same key again changes nothing').toEqual({ key: KEY_A, gen: G(3) });
  await pasteCard(A, await zed.signed({ key: KEY_B, gen: G(3) }, 'Someone Else'), CONFLICT, /Someone Else/);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'e3'), 'a different key at the same generation leaves the held key alone').toEqual({ key: KEY_A, gen: G(3) });
  // A newer SIGNED card (the card carries another display name on purpose): the held key is REPLACED, release-first, and the line names the BOOK's contact, never the card's name.
  // The pair was never confirmed (nothing writes the confirmed set in production yet), so only the first sentence appears, not "unconfirmed again".
  await pasteCard(A, await zed.signed({ key: KEY_B, gen: G(4) }, 'Someone Else'), /A newer signed card from Zedcontact has changed the security details saved here for them\./, /Someone Else|unconfirmed/);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'e4'), 'a valid HIGHER generation replaces the held key and its generation').toEqual({ key: KEY_B, gen: G(4) });
  await pasteCard(A, await zed.signed({ key: KEY_A, gen: G(3) }), /already have/i);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'e4b'), 'CONTROL: an OLDER generation afterwards is a rollback: kept as it is, nothing replaced back').toEqual({ key: KEY_B, gen: G(4) });
  const yan = await nodeIdentity('Yancontact');
  await pasteCard(A, await yan.signed({ key: KEY_B, gen: G(2) }), /added successfully|added/i);
  expect(await storedBeacon(A, /yancontact/i, testInfo, 'e5'), 'a NEW contact gets the key and its generation at add').toEqual({ key: KEY_B, gen: G(2) });
  await ctx.close();
});

// TODAY'S OUTCOME on a PRODUCTION build, stated on purpose: its CSP refuses WebAssembly, so the beacon curve check cannot run and the card's beacon key is
// DROPPED (counted, never stored). The card itself is still imported and no beacon request is made. When the CSP is changed to allow 'wasm-unsafe-eval' for
// the opted-in build, this case must be updated deliberately: it must not start passing or failing by accident.
test('PRODUCTION CSP (today): a card with a beacon key is still added, the key is DROPPED, and no beacon request is made', async ({ browser }, testInfo) => {
  test.skip(!process.env.E2E_PROD, 'only meaningful on a production build (E2E_PROD=1)');
  test.setTimeout(240_000);
  const KEY_A = await beaconPublicKey(BigInt('111111'));
  const ctx = await browser.newContext(); const A = await ctx.newPage();
  const beaconRequests: string[] = [];
  A.on('request', (r) => { if (/\/beacon\//.test(r.url())) beaconRequests.push(r.url()); });
  await genesis(A, 'Alice Prod');
  const zed = await nodeIdentity('Zedcontact');
  await pasteCard(A, await zed.signed({ key: KEY_A, gen: G(3) }), /added successfully|added/i);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'p0'), 'the contact was added, but a production CSP cannot run the curve check, so no beacon key is stored').toEqual({ key: undefined, gen: undefined });
  expect(beaconRequests, 'and nothing was sent to a beacon route').toEqual([]);
  await ctx.close();
});

// ---------- the empty confirmed set, observed in a real browser ----------
// A Grow link built in Node exactly as the app builds one (AES-256-GCM, the key only in the URL fragment, the blob POSTed to the relay), so the ceremony can be driven with a
// card that carries a beacon key; the app's own card builder never includes one.
async function craftLink(page: Page, signedCard: string): Promise<string> {
  const subtle = webcrypto.subtle;
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(signedCard)));
  const packed = new Uint8Array(12 + ct.length); packed.set(iv, 0); packed.set(ct, 12);
  const res = await page.request.post('/api/relay', { data: { encrypted: Buffer.from(packed).toString('base64url') } });
  expect(res.ok(), 'the relay accepted the blob').toBeTruthy();
  const { code } = await res.json() as { code: string };
  const fragment = Buffer.from(await subtle.exportKey('raw', key)).toString('base64url');
  return `${new URL(page.url()).origin}/c/${code}#${fragment}`;
}
async function openGrow(page: Page) {
  const pill = page.getByTestId('nav-grow');
  if (await pill.isVisible().catch(() => false)) { await pill.click(); return; }
  await page.getByTestId('top-nav-menu-btn').click();
  await page.getByTestId('nav-grow-menu').click();
}
async function joinExisting(page: Page, link: string) {
  await openGrow(page);
  const dialog = page.getByTestId('grow-surface');
  await dialog.getByRole('tab', { name: 'Scan / paste' }).click();
  await dialog.getByLabel(/paste your invite link/i).fill(link);
  await dialog.getByRole('button', { name: /^join$/i }).click();
  await expect(page.getByTestId('join-add-to-gate')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('join-add-to-gate').click();
  await expect(page.getByText(/already connected/i).first()).toBeVisible({ timeout: 60_000 });
  // the done screen's only way out reloads the app, which locks the session: unlock again (the same step the gate spec takes), so the next helper can reach the tabs
  await page.goto('/');
  await page.getByPlaceholder('Enter passphrase').fill(PW);
  await page.getByPlaceholder('Enter passphrase').press('Enter');
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 60_000 });
}
/** every key of the settings store (names only: the rows stay sealed) */
async function settingsKeys(page: Page): Promise<string[]> {
  return page.evaluate(() => new Promise<string[]>((resolve, reject) => {
    const open = indexedDB.open('svrnty');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const req = db.transaction('settings', 'readonly').objectStore('settings').getAllKeys();
      req.onerror = () => { db.close(); reject(req.error); };
      req.onsuccess = () => { db.close(); resolve((req.result as unknown[]).map(String)); };
    };
  }));
}

test('NO SOURCE CONFIRMS A PAIR (runtime): a held contact + a MATCHING card through the real Grow ceremony AND the real paste import: the key is kept, NO confirmed row exists, and no beacon request is made', async ({ browser }, testInfo) => {
  test.skip(!!process.env.E2E_PROD, 'needs WebAssembly (the curve check) so the key is accepted: run on next dev');
  test.setTimeout(480_000);
  const KEY_A = await beaconPublicKey(BigInt('111111'));
  const ctx = await browser.newContext(); const A = await ctx.newPage();
  const beaconRequests: string[] = [];
  A.on('request', (r) => { if (/\/beacon\//.test(r.url())) beaconRequests.push(r.url()); });
  await genesis(A, 'Alice Runtime');
  const zed = await nodeIdentity('Zedcontact');
  await pasteCard(A, await zed.signed(), /added successfully|added/i);                                 // Zed is now a HELD contact with no beacon key
  // 1. the real ceremony, existing-contact branch, a card carrying the key: it back-fills (the ceremony's key branch, in a browser for the first time)
  await joinExisting(A, await craftLink(A, await zed.signed({ key: KEY_A, gen: G(3) })));
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'r1'), 'the ceremony back-fills the key').toEqual({ key: KEY_A, gen: G(3) });
  // 2. a MATCHING card (same key, same generation) through the ceremony and through the paste import: the case that would confirm if any source could
  await joinExisting(A, await craftLink(A, await zed.signed({ key: KEY_A, gen: G(3) })));
  await pasteCard(A, await zed.signed({ key: KEY_A, gen: G(3) }), /already have/i);
  expect(await storedBeacon(A, /zedcontact/i, testInfo, 'r2'), 'a matching card changes nothing').toEqual({ key: KEY_A, gen: G(3) });
  // 3. the empty set: NO confirmed row exists, and the reader is not simply broken (CONTROL: the settings store is readable and holds other rows)
  const keys = await settingsKeys(A);
  expect(keys.length, 'CONTROL: the settings store is readable and not empty').toBeGreaterThan(0);
  expect(keys.filter((k) => k.startsWith('beacon_confirmed:')), 'no source confirmed a pair: there is no confirmed row').toEqual([]);
  expect(beaconRequests, 'and nothing was sent to a beacon route').toEqual([]);
  await ctx.close();
});
