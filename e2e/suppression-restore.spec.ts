import { test, expect, type Browser, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { unpackVault } from '../src/lib/sync/vault';

// The owner's blocks, groups and removed contacts travel in the password-sealed vault and come back on a new device, in a REAL browser: real IndexedDB, the real sealed rows, the real export
// dialog and the real restore screen. The page is driven through a small esbuild-bundled harness that calls the app's own store functions; nothing is stubbed.
//
// What each test pins:
//   1. carried: a record with a person, a group and a removed contact goes into the vault exactly (read back in Node from the unpacked vault), with NO notice on the export screen;
//   2. restore onto a new device: the persons, the group and the removed contact are back, global is ON (dark) whatever the backup said, a confirmation is waiting and names no loosening
//      until the person confirms; and a later backup that says global ON clears that waiting "off" (S1);
//   3. nothing to carry: a person who never blocked or removed anyone gets no notice and no field;
//   4. left out: a record that exists but cannot be read shows the notice BEFORE the file is saved, does not stop the export, and the vault carries nothing.
test.use({ bypassCSP: true }); // the harness is injected with addScriptTag, which the page's script policy refuses, as it should

const APP = 'http://localhost:3000/';
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
const hex = (n: number): string => n.toString(16).padStart(64, '0');
const P1 = hex(1), P2 = hex(2), P3 = hex(4), R1 = hex(8);
const NOTICE = 'suppression-left-out-notice';

// circomlibjs is reached by client-store only through a dynamic import() on the flagged beacon path; esbuild must resolve it at build time and these harnesses never call it.
const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });

async function mint(page: Page, name: string) {
  await page.goto(APP);
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 45_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
  await page.addScriptTag({ content: bundle('e2e/helpers/suppression-restore-harness.ts') });
  await page.evaluate((p) => window.__sup.init(p), UNLOCK_PW);
}

/** Open the full-backup dialog and go as far as the passphrase step, where the export screen has already looked at what the vault will carry. */
async function toPassphraseStep(page: Page) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByTestId('vault-export-passphrase')).toBeVisible({ timeout: 15_000 });
}

async function finishExport(page: Page, dest: string) {
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  await (await downloadPromise).saveAs(dest);
}

const carriedIn = async (path: string): Promise<Record<string, unknown> | undefined> => {
  const { contents } = await unpackVault(readFileSync(path).buffer.slice(0) as ArrayBuffer, EXPORT_PW);
  return (contents as unknown as { trustGraph: { suppression?: Record<string, unknown> } }).trustGraph.suppression;
};
const sorted = (x: unknown): string[] => [...(x as string[])].sort();

async function restoreOnNewDevice(browser: Browser, vaultPath: string) {
  const ctx = await browser.newContext({ bypassCSP: true });
  const p = await ctx.newPage();
  await p.goto(APP);
  await p.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await p.setInputFiles('[data-testid="restore-file-input"]', vaultPath);
  await p.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
  await p.getByRole('button', { name: /^restore identity$/i }).click();
  await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
  await p.addScriptTag({ content: bundle('e2e/helpers/suppression-restore-harness.ts') });
  await p.evaluate((pw) => window.__sup.init(pw), EXPORT_PW); // a vault restore leaves the vault passphrase as the device passphrase
  return { ctx, p };
}

test.describe.configure({ mode: 'serial' });

let ownerA = '';
let vaultCarried = '';

test('1 carried: a record with a person, a group and a removed contact goes into the vault exactly, and the export screen shows NO notice', async ({ browser }, testInfo) => {
  test.setTimeout(240_000);
  const ctx = await browser.newContext({ bypassCSP: true });
  const page = await ctx.newPage();
  await mint(page, 'Suppression Carry E2E');
  ownerA = (await page.evaluate(() => window.__sup.owner())) ?? '';
  expect(ownerA).not.toBe('');
  await page.evaluate(([o, a, b, r]) => window.__sup.seed(o, { global: false, groups: ['family'], persons: [a, b] }).then(() => window.__sup.remove(o, r)), [ownerA, P1, P2, R1]);
  expect(await page.evaluate((o) => window.__sup.status(o), ownerA)).toBe('carried');

  await toPassphraseStep(page);
  await expect(page.getByTestId(NOTICE)).toHaveCount(0);
  vaultCarried = testInfo.outputPath('carried.svrnty');
  await finishExport(page, vaultCarried);
  await ctx.close();

  const s = await carriedIn(vaultCarried);
  expect(s, 'the vault carries the record').toBeDefined();
  expect(s!.v).toBe(1);
  expect(s!.global).toBe(false);
  expect(sorted(s!.groups)).toEqual(['family']);
  expect(sorted(s!.persons)).toEqual([P1, P2]);
  expect(sorted(s!.removed)).toEqual([R1]);
});

test('2 restore onto a new device brings it back dark; a later backup that says global ON clears the waiting "off" (S1)', async ({ browser }) => {
  test.setTimeout(180_000);
  expect(vaultCarried, 'test 1 produced the vault').not.toBe('');
  const { ctx, p } = await restoreOnNewDevice(browser, vaultCarried);
  const owner = (await p.evaluate(() => window.__sup.owner())) ?? '';
  expect(owner, 'the restored identity is the same owner').toBe(ownerA);

  const after = await p.evaluate((o) => window.__sup.read(o), owner);
  expect(after.record, 'the record is readable').not.toBeNull();
  expect(after.record!.global, 'global is ON (dark) whatever the backup said').toBe(true);
  expect(sorted(after.record!.persons)).toEqual([P1, P2]);
  expect(sorted(after.record!.groups)).toEqual(['family']);
  expect((after.removed as { state: string; value: string[] }).state).toBe('ok');
  expect((after.removed as { value: string[] }).value).toEqual([R1]);
  const pending = after.pending as { state: string; value?: { v: number; backup_at: string | null; restored_at: string } };
  expect(pending.state, 'the backup said global off, so a confirmation is waiting').toBe('ok');
  expect(pending.value!.restored_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

  // S1: a newer backup that says global ON supersedes the waiting off.
  await p.evaluate(([o, c]) => window.__sup.restore(o, c, '2026-11-17T12:00:00.000Z'), [owner, { v: 1, global: true, groups: [], persons: [P3], removed: [] }] as const);
  const later = await p.evaluate((o) => window.__sup.read(o), owner);
  expect((later.pending as { state: string }).state, 'the older off is no longer waiting').toBe('absent');
  expect(later.record!.global).toBe(true);
  expect(sorted(later.record!.persons), 'nothing the device held was dropped, and the new person was added').toEqual([P1, P2, P3]);
  expect(await p.evaluate((o) => window.__sup.confirm(o), owner), 'and it can no longer be confirmed').toBe('no-pending');
  expect((await p.evaluate((o) => window.__sup.read(o), owner)).record!.global).toBe(true);
  await ctx.close();
});

test('2b the confirmation turns global OFF only when the marker is there (a fresh restore of the same vault)', async ({ browser }) => {
  test.setTimeout(180_000);
  const { ctx, p } = await restoreOnNewDevice(browser, vaultCarried);
  const owner = (await p.evaluate(() => window.__sup.owner())) ?? '';
  expect(await p.evaluate((o) => window.__sup.confirm(o), owner)).toBe('confirmed');
  const done = await p.evaluate((o) => window.__sup.read(o), owner);
  expect(done.record!.global).toBe(false);
  expect(sorted(done.record!.persons), 'the people stay suppressed after the confirmation').toEqual([P1, P2]);
  expect((done.pending as { state: string }).state).toBe('absent');
  await ctx.close();
});

test('3 nothing to carry: a person who never blocked or removed anyone gets no notice and the vault has no field', async ({ browser }, testInfo) => {
  test.setTimeout(240_000);
  const ctx = await browser.newContext({ bypassCSP: true });
  const page = await ctx.newPage();
  await mint(page, 'Suppression None E2E');
  const owner = (await page.evaluate(() => window.__sup.owner())) ?? '';
  expect(await page.evaluate((o) => window.__sup.status(o), owner)).toBe('nothing-to-carry');
  await toPassphraseStep(page);
  await expect(page.getByTestId(NOTICE), 'no notice: there is nothing to lose').toHaveCount(0);
  const dest = testInfo.outputPath('none.svrnty');
  await finishExport(page, dest);
  await ctx.close();
  expect(await carriedIn(dest)).toBeUndefined();
});

test('4 left out: a record that exists but cannot be read shows the notice BEFORE the file is saved, does not stop the export, and the vault carries nothing', async ({ browser }, testInfo) => {
  test.setTimeout(240_000);
  const ctx = await browser.newContext({ bypassCSP: true });
  const page = await ctx.newPage();
  await mint(page, 'Suppression Left Out E2E');
  const owner = (await page.evaluate(() => window.__sup.owner())) ?? '';
  await page.evaluate(([o, a]) => window.__sup.seed(o, { global: false, groups: [], persons: [a] }), [owner, P1]);
  expect(await page.evaluate((o) => window.__sup.status(o), owner), 'control: readable, so carried').toBe('carried');
  await page.evaluate((o) => window.__sup.corrupt(o), owner);
  expect(await page.evaluate((o) => window.__sup.status(o), owner), 'the row exists but cannot be read: left out, not "nothing"').toBe('left-out');

  await toPassphraseStep(page);
  await expect(page.getByTestId(NOTICE), 'the notice is on the screen before anything is saved').toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId(NOTICE)).toContainText(/blocked or removed/i);
  const dest = testInfo.outputPath('leftout.svrnty');
  await finishExport(page, dest); // the export still works
  await ctx.close();
  expect(await carriedIn(dest), 'nothing was carried').toBeUndefined();
});
