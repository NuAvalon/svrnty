import { test, expect, type Page } from '@playwright/test';

// E2E persistence gate for the recovery-canonical launch-blocker (PR#110).
//
// What #110 fixes: on restore (both the vault-passphrase adapter and the recovery-code/seed
// adapter) the reconstructed identity must carry the CANONICAL 64-hex fingerprint and have its
// post-quantum public keys (ML-DSA-87 sig + ML-KEM-1024 kem) repopulated — and it must SURVIVE a
// reload (the bb92dd3-class persistence bug: identity written to memory but not IndexedDB).
//
// Why this gate exists: the crypto self-test proves reconstruct() is byte-correct, but not that
// the full UI -> adapter -> IndexedDB -> reload chain actually lands a canonical, persisted
// identity. CI-green != live-works. This drives the real UI on both paths and asserts against
// IndexedDB directly (the owner-card UI truncates the fingerprint to 32 hex, so it can't be used
// for a canonical assertion — we read the store).
//
// Shape per path: mint (context A) -> export encrypted .svrnty -> restore in a FRESH context B
// (empty IndexedDB = new device) -> assert canonical fp + PQ pubs in IndexedDB -> reload ->
// re-assert (persistence). The minted fingerprint is compared against the restored one.

const APP = 'http://localhost:3000/';
const NAME = 'Recovery E2E';
// Deliberately distinct: the unlock passphrase (keys-at-rest) is NOT the export encryption
// password. Restore(vault path) must accept the EXPORT password, so keeping them different guards
// against a path that wrongly expects the unlock passphrase.
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
// Blocker-C: recovery-code (seed) restore now sets a NEW >=12-char device passphrase so the
// recovered keys are encrypted at rest (no passphrase-free path). Kept distinct from UNLOCK_PW /
// EXPORT_PW to guard against a path that confuses the three.
const RECOVER_PW = 'recover-e2e-pass-9012';
const HEX64 = /^[0-9a-f]{64}$/;

// Reads the canonical identity straight from IndexedDB for the active fingerprint.
// Store shapes (src/lib/identity/client-store.ts): settings/active_fingerprint = {key,value};
// identities/<fp> = {fingerprint, data:{identity:{fingerprint}, post_quantum:{sig_public_key,
// kem_public_key}, next_authority_commitment, durable:{epoch}}}. The rotation-authority anchor
// (next_authority_commitment + durable) is written at the data WRAPPER top level — a SIBLING of
// .identity and .post_quantum — by both genesis (browser-identity.ts) and seed restore
// (seedVaultRestore.ts). Open without a version so we attach to whatever the app created (v3),
// never forcing an upgrade.
async function readCanonical(page: Page) {
  return page.evaluate(async () => {
    const openDb = () =>
      new Promise<IDBDatabase>((res, rej) => {
        const r = indexedDB.open('svrnty');
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
    const db = await openDb();
    const get = (store: string, key: string) =>
      new Promise<any>((res, rej) => {
        const rq = db.transaction(store, 'readonly').objectStore(store).get(key);
        rq.onsuccess = () => res(rq.result);
        rq.onerror = () => rej(rq.error);
      });
    const active = await get('settings', 'active_fingerprint');
    const fp = active?.value ?? null;
    if (!fp) return { activeFp: null, idFp: null, sigPub: null, kemPub: null, nac: null, epoch: null };
    const rec = await get('identities', fp);
    return {
      activeFp: fp,
      idFp: rec?.data?.identity?.fingerprint ?? null,
      sigPub: rec?.data?.post_quantum?.sig_public_key ?? null,
      kemPub: rec?.data?.post_quantum?.kem_public_key ?? null,
      // Rotation authority anchor (T2.4): genesis + restore write next_authority_commitment and
      // durable at the identity WRAPPER top level. Read wrapper-aware (mirrors the production read
      // in identity-card-sign.ts:157) so the gate guards a persisted, readable anchor rather than
      // a brittle exact sub-path.
      nac: rec?.data?.next_authority_commitment ?? rec?.data?.identity?.next_authority_commitment ?? null,
      epoch: rec?.data?.durable?.epoch ?? rec?.data?.identity?.durable?.epoch ?? null,
    };
  });
}

function assertCanonical(
  snap: { idFp: string | null; sigPub: unknown; kemPub: unknown; nac: string | null; epoch: number | null },
  expectedFp: string,
  expectedNac: string,
) {
  expect(snap.idFp).toBe(expectedFp);
  expect(snap.idFp ?? '').toMatch(HEX64);
  expect(snap.sigPub).toBeTruthy(); // ML-DSA-87 sig public key repopulated
  expect(snap.kemPub).toBeTruthy(); // ML-KEM-1024 kem public key repopulated
  // Rotation authority anchor (T2.4 regression-lock): the restore must reproduce the genesis
  // next_authority_commitment (compared against the value captured at mint — capture-at-mint, no
  // recompute so no crypto import) and stay at durable.epoch 0. Without this a seed/vault-restored
  // identity would silently lose the ability to verify its own rotations. Guards the dropped-field,
  // wrong-value, and wrong-epoch regression classes; a future edit that breaks any of them fails CI.
  expect(snap.nac).toBe(expectedNac);
  expect(snap.nac ?? '').toMatch(HEX64);
  expect(snap.epoch).toBe(0);
}

// Drives the real create-identity flow to the unlocked app; returns the canonical fingerprint and
// the one-time recovery code (needed for the seed-restore path).
async function mint(page: Page): Promise<{ fp: string; recoveryCode: string; nac: string }> {
  await page.goto(APP);
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(NAME);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();

  // One-time recovery reveal — real in-browser keygen runs first, so wait generously. Capture the
  // recovery code before acknowledging (it is shown once).
  const seed = page.getByTestId('seed-phrase-display');
  await expect(seed).toBeVisible({ timeout: 45_000 });
  const recoveryCode = ((await seed.textContent()) ?? '').trim();
  expect(recoveryCode).toMatch(/^[0-9a-f]{8}( [0-9a-f]{8}){7}$/);
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
  const minted = await readCanonical(page);
  const fp = minted.idFp;
  expect(fp ?? '').toMatch(HEX64);
  // Capture the genesis rotation-authority anchor here (context A) so each restore path can be
  // asserted to reproduce it EXACTLY. Assert it is a real 64-hex value at mint so a wrong/renamed
  // storage path fails loudly here instead of silently passing a null===null compare downstream.
  const nac = minted.nac;
  expect(nac ?? '').toMatch(HEX64);
  expect(minted.epoch).toBe(0); // genesis epoch
  return { fp: fp!, recoveryCode, nac: nac! };
}

// Exports an encrypted v4 .svrnty vault (Argon2id/AES-256-GCM) and returns the saved file path.
async function exportVault(page: Page, dest: string): Promise<string> {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('full-backup-open').click();
  // Export-behind-auth: re-enter the unlock passphrase.
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  // Choose the export encryption password.
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/\.svrnty$/i);
  await download.saveAs(dest);
  return dest;
}

async function openRestoreWithFile(page: Page, vaultPath: string) {
  await page.goto(APP);
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  // Hidden <input type=file accept=".svrnty,.json">; setInputFiles works on it directly.
  await page.setInputFiles('input[accept=".svrnty,.json"]', vaultPath);
}

test.describe('recovery-canonical persistence gate (PR#110)', () => {
  test('vault-passphrase restore lands a canonical identity that survives reload', async ({ page, browser }, testInfo) => {
    test.setTimeout(150_000);

    const { fp, nac } = await mint(page);
    const vaultPath = await exportVault(page, testInfo.outputPath('vault.svrnty'));

    // Fresh device: empty IndexedDB.
    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    await openRestoreWithFile(p, vaultPath);
    await p.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
    await p.getByRole('button', { name: /^restore identity$/i }).click();
    await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });

    assertCanonical(await readCanonical(p), fp, nac);

    await p.reload();
    await p.waitForLoadState('domcontentloaded');
    assertCanonical(await readCanonical(p), fp, nac); // persisted across reload

    await ctx.close();
  });

  test('recovery-code (seed) restore lands a canonical identity that survives reload', async ({ page, browser }, testInfo) => {
    test.setTimeout(150_000);

    const { fp, recoveryCode, nac } = await mint(page);
    const vaultPath = await exportVault(page, testInfo.outputPath('vault.svrnty'));

    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    await openRestoreWithFile(p, vaultPath);
    // v4 vault exposes the recovery-code (seed) path. Blocker-C: this path is no longer
    // passphrase-free — recovered keys must be encrypted at rest, so the user sets a >=12-char
    // device passphrase up front and "Recover my identity" stays disabled until it is provided
    // (3a-pure: initSessionKey before the first write, no plaintext window even transiently).
    await p.getByRole('button', { name: /recover with your recovery code/i }).click();
    await p.getByPlaceholder(/enter your recovery code/i).fill(recoveryCode);
    await p.getByPlaceholder(/at least 12 characters/i).fill(RECOVER_PW);
    await p.getByRole('button', { name: /^recover my identity$/i }).click();

    // The seed path lands on the contacts-honesty interstitial (identity is already written to
    // IndexedDB inside handleSeedVaultRestore, before this screen), not directly on the app tabs.
    await expect(p.getByRole('heading', { name: /your identity is back/i })).toBeVisible({ timeout: 30_000 });
    assertCanonical(await readCanonical(p), fp, nac);

    // Continue into the app, then prove the recovered identity survives a reload.
    await p.getByRole('button', { name: /^continue$/i }).click();
    await p.reload();
    await p.waitForLoadState('domcontentloaded');
    assertCanonical(await readCanonical(p), fp, nac); // persisted across reload

    await ctx.close();
  });
});
