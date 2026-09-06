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
const HEX64 = /^[0-9a-f]{64}$/;

// Reads the canonical identity straight from IndexedDB for the active fingerprint.
// Store shapes (src/lib/identity/client-store.ts): settings/active_fingerprint = {key,value};
// identities/<fp> = {fingerprint, data:{identity:{fingerprint}, post_quantum:{sig_public_key,
// kem_public_key}}}. Open without a version so we attach to whatever the app created (v3), never
// forcing an upgrade.
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
    if (!fp) return { activeFp: null, idFp: null, sigPub: null, kemPub: null };
    const rec = await get('identities', fp);
    return {
      activeFp: fp,
      idFp: rec?.data?.identity?.fingerprint ?? null,
      sigPub: rec?.data?.post_quantum?.sig_public_key ?? null,
      kemPub: rec?.data?.post_quantum?.kem_public_key ?? null,
    };
  });
}

function assertCanonical(snap: { idFp: string | null; sigPub: unknown; kemPub: unknown }, expectedFp: string) {
  expect(snap.idFp).toBe(expectedFp);
  expect(snap.idFp ?? '').toMatch(HEX64);
  expect(snap.sigPub).toBeTruthy(); // ML-DSA-87 sig public key repopulated
  expect(snap.kemPub).toBeTruthy(); // ML-KEM-1024 kem public key repopulated
}

// Drives the real create-identity flow to the unlocked app; returns the canonical fingerprint and
// the one-time recovery code (needed for the seed-restore path).
async function mint(page: Page): Promise<{ fp: string; recoveryCode: string }> {
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
  const fp = (await readCanonical(page)).idFp;
  expect(fp ?? '').toMatch(HEX64);
  return { fp: fp!, recoveryCode };
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

    const { fp } = await mint(page);
    const vaultPath = await exportVault(page, testInfo.outputPath('vault.svrnty'));

    // Fresh device: empty IndexedDB.
    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    await openRestoreWithFile(p, vaultPath);
    await p.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
    await p.getByRole('button', { name: /^restore identity$/i }).click();
    await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });

    assertCanonical(await readCanonical(p), fp);

    await p.reload();
    await p.waitForLoadState('domcontentloaded');
    assertCanonical(await readCanonical(p), fp); // persisted across reload

    await ctx.close();
  });

  test('recovery-code (seed) restore lands a canonical identity that survives reload', async ({ page, browser }, testInfo) => {
    test.setTimeout(150_000);

    const { fp, recoveryCode } = await mint(page);
    const vaultPath = await exportVault(page, testInfo.outputPath('vault.svrnty'));

    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    await openRestoreWithFile(p, vaultPath);
    // v4 vault exposes the passphrase-free path.
    await p.getByRole('button', { name: /recover with your recovery code/i }).click();
    await p.getByPlaceholder(/enter your recovery code/i).fill(recoveryCode);
    await p.getByRole('button', { name: /^recover my identity$/i }).click();

    // The seed path lands on the contacts-honesty interstitial (identity is already written to
    // IndexedDB inside handleSeedVaultRestore, before this screen), not directly on the app tabs.
    await expect(p.getByRole('heading', { name: /your identity is back/i })).toBeVisible({ timeout: 30_000 });
    assertCanonical(await readCanonical(p), fp);

    // Continue into the app, then prove the recovered identity survives a reload.
    await p.getByRole('button', { name: /^continue$/i }).click();
    await p.reload();
    await p.waitForLoadState('domcontentloaded');
    assertCanonical(await readCanonical(p), fp); // persisted across reload

    await ctx.close();
  });
});
