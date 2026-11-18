import { test, expect, type Browser, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import type { KeyProbe } from './helpers/key-unlock-harness';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * A key backup that is restored and then exported AGAIN must still carry a key that opens. The identity key is stored with the passphrase it was made with; the screens that use it
 * (signing, the owner message keys) unlock it with that stored passphrase. A restore path that stored an empty passphrase, or an export that read a stale one, would hand the next device a
 * key it cannot unlock, silently. This drives the real screens through two hops and asks the app's OWN functions whether the key is usable after each:
 *
 *   A mints            -> A exports a full vault (V1)
 *   B restores V1      -> B exports a full vault (V2) AND "Download Keys" (K2)
 *   C restores V2      (a second full-vault hop)
 *   D restores K2      (the key file, a key-only restore: no profile, so only the unlock gate is asked)
 *
 * "Usable" = the unlock gate that signing and decrypting share (unlockArmoredIdentityKey) accepts the stored key and passphrase, and, where there is an identity record, the owner message keys
 * assemble (loadOwnerRatchetIdentity, which returns null on any failure). The probe reports booleans and a passphrase LENGTH only. The assertions are soft, so a red run names every hop that broke.
 *
 * Bounds: the harness's init runs the (idempotent) unlock migrations with the same passphrase on B, C and D once the restore has finished: a test-side write that cannot create a passphrase, so it does not
 * touch this question. `bypassCSP` is test-context only; this spec says nothing about the page's script policy. It runs on `next dev`, not a production build.
 *
 * NOT driven: a real NOTE between two people (it needs a sender); the unlock gate and the owner message keys are what a note's decrypt path uses. NOT covered: a passphrase CHANGE before the
 * export: "Set Passphrase" is switched off until the re-key fix ships (set-passphrase-hidden.spec.ts), so no screen reaches it.
 */
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW_1 = 'export-hop-one-pass-1111';
const EXPORT_PW_2 = 'export-hop-two-pass-2222';
const KEY_PW = 'key-file-hop-pass-3333';

test.setTimeout(900_000);
// A click that cannot land (an overlay, a missing control) must fail in a minute, not wait out the whole test timeout.
test.use({ actionTimeout: 60_000 });

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function mint(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 90_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 60_000 });
}

async function inject(page: Page, passphrase: string) {
  await page.addScriptTag({ content: bundle('e2e/helpers/key-unlock-harness.ts') });
  await page.evaluate((p) => window.__ku.init(p), passphrase);
}

/** Full-backup export from a device whose everyday passphrase is `unlockPw`. */
async function exportVault(page: Page, unlockPw: string, exportPw: string, dest: string) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(unlockPw);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByTestId('vault-export-passphrase')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('vault-export-passphrase').fill(exportPw);
  await page.getByTestId('vault-export-confirm').fill(exportPw);
  const download = page.waitForEvent('download', { timeout: 240_000 });
  await page.getByTestId('vault-export-download').click();
  await (await download).saveAs(dest);
  // The "Vault downloaded" dialog stays open over the page and would intercept the next click: close it and wait for it to go.
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
}

/** "Download Keys" from a device whose everyday passphrase is `unlockPw`. */
async function downloadKeys(page: Page, unlockPw: string, keyPw: string, dest: string) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByText('Download Keys', { exact: true }).click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(unlockPw);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByPlaceholder('Enter a strong password')).toBeVisible({ timeout: 60_000 });
  await page.getByPlaceholder('Enter a strong password').fill(keyPw);
  await page.getByPlaceholder('Confirm your password').fill(keyPw);
  const download = page.waitForEvent('download', { timeout: 240_000 });
  await page.getByRole('button', { name: /download encrypted key/i }).click();
  await (await download).saveAs(dest);
}

/** A fresh device: pick a backup file at the gate and enter its password. */
async function openGateRestore(browser: Browser, file: string, password: string) {
  const ctx = await browser.newContext({ bypassCSP: true, acceptDownloads: true });
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
  await page.getByPlaceholder('Encryption password from export').fill(password);
  return { ctx, page };
}

const say = (hop: string, p: KeyProbe) => console.log(`HOP ${hop}`, JSON.stringify({ ...p, fingerprint: p.fingerprint.slice(0, 8) }));

test('a key that was restored and exported again still opens on the next device (two full-vault hops, and the key file)', async ({ browser }, testInfo) => {
  // A: mint, baseline, export V1
  const ctxA = await browser.newContext({ bypassCSP: true, acceptDownloads: true });
  const a = await ctxA.newPage();
  await mint(a, 'Hop A');
  await inject(a, UNLOCK_PW);
  const probeA = await a.evaluate(() => window.__ku.probe());
  say('A (minted here)', probeA);
  expect(probeA.hasKey && probeA.unlocks, 'CONTROL: the key made on device A opens on device A').toBe(true);
  expect(probeA.ownerMessageKeys, 'CONTROL: the owner message keys assemble on device A').toBe(true);
  const v1 = testInfo.outputPath('v1.svrnty');
  await exportVault(a, UNLOCK_PW, EXPORT_PW_1, v1);
  await ctxA.close();

  // B: restore V1; probe; export V2 and K2 (a vault restore leaves the vault passphrase as the device passphrase)
  const { ctx: ctxB, page: b } = await openGateRestore(browser, v1, EXPORT_PW_1);
  await b.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await expect(b.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 240_000 });
  await inject(b, EXPORT_PW_1);
  const probeB = await b.evaluate(() => window.__ku.probe());
  say('B (restored from A)', probeB);
  expect.soft(probeB.fingerprint, 'B restored the same identity').toBe(probeA.fingerprint);
  expect.soft(probeB.hasKey && probeB.unlocks, 'HOP 1: the key restored from the first vault opens on B').toBe(true);
  expect.soft(probeB.ownerMessageKeys, 'HOP 1: the owner message keys assemble on B').toBe(true);
  const v2 = testInfo.outputPath('v2.svrnty');
  const k2 = testInfo.outputPath('keys-b.svrnty-keys');
  await exportVault(b, EXPORT_PW_1, EXPORT_PW_2, v2);
  await downloadKeys(b, EXPORT_PW_1, KEY_PW, k2);
  await ctxB.close();

  // C: restore V2 (second full-vault hop)
  const { ctx: ctxC, page: c } = await openGateRestore(browser, v2, EXPORT_PW_2);
  await c.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  await expect(c.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 240_000 });
  await inject(c, EXPORT_PW_2);
  const probeC = await c.evaluate(() => window.__ku.probe());
  say('C (restored from B\'s vault)', probeC);
  expect.soft(probeC.fingerprint, 'C restored the same identity').toBe(probeA.fingerprint);
  expect.soft(probeC.hasKey && probeC.unlocks, 'HOP 2: the key re-exported by B (full vault) opens on C').toBe(true);
  expect.soft(probeC.ownerMessageKeys, 'HOP 2: the owner message keys assemble on C').toBe(true);
  await ctxC.close();

  // D: restore B's key file (a key-only restore: no profile on this device, so only the unlock gate is asked)
  const { ctx: ctxD, page: d } = await openGateRestore(browser, k2, KEY_PW);
  await d.getByRole('button', { name: /^(open vault|restore identity)$/i }).click();
  // Wait for the app's OWN end-of-restore signal BEFORE injecting the harness. The harness is a separate bundle of the store, and its init can generate and write the key-encryption salt: injected
  // while the restore is still deriving its key it would race that derivation (two salts, last writer wins) and write into the very operation under test.
  await expect(d.getByText(/Your identity key is saved on this device/)).toBeVisible({ timeout: 240_000 });
  await inject(d, KEY_PW);
  await expect.poll(async () => (await d.evaluate((fp) => window.__ku.probe(fp), probeA.fingerprint)).hasKey, { timeout: 30_000, message: 'the key file restored a key on D' }).toBe(true);
  const probeD = await d.evaluate((fp) => window.__ku.probe(fp), probeA.fingerprint);
  say('D (key file from B)', probeD);
  expect.soft(probeD.unlocks, 'HOP 2 (key file): the key file B exported opens on D').toBe(true);
  await ctxD.close();
});
