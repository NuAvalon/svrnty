import { test, expect, type Browser, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { unpackVault } from '../src/lib/sync/vault';

test.use({ bypassCSP: true }); // the harness is injected with addScriptTag, which the page's script policy refuses, as it should

const APP = 'http://localhost:3000/';
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
const hex = (n: number): string => n.toString(16).padStart(64, '0');
const P1 = hex(1), P2 = hex(2), P3 = hex(4), R1 = hex(8);
const NOTICE = 'suppression-left-out-notice';
const LEFT_OUT_SENTENCE = "This backup doesn't include your list of blocked and removed people, because it couldn't be added to the file. Your contacts are included. If you restore from this backup, you'll need to block or remove those people again; until then, the restored device stays private.";

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


const NOT_LIVE = "Showing up in other people's trust maps isn't live yet. Your choice is saved and will apply when it is.";
const STATE_ON = "You're set to show up in the trust maps of the people you're connected to.";
const STATE_OFF = "You're set to stay out of other people's trust maps.";
const CONFIRM = "Set yourself to show up in the trust maps of the people you're connected to?";
const ABSENT = "This device has no trust-map setting saved, so it can't be changed here.";
const UNREADABLE = "Your trust-map setting couldn't be read on this device, so it can't be changed here.";

/** Identity tab -> Actions -> Lenses & vault: the panel that holds the setting. */
async function openSetting(p: Page) {
  await p.getByRole('tab', { name: 'Identity', exact: true }).click();
  await p.getByTestId('card-actions-toggle').click();
  await p.getByRole('menuitem', { name: 'Lenses & vault' }).click();
  const section = p.getByTestId('trust-map-settings');
  await expect(section).toBeVisible({ timeout: 15_000 });
  return section;
}

// A person restored from a backup that said "visible" is private and has a waiting "off". The setting: shows that stored state with the not-live line; Show up asks first (Cancel writes nothing); Show up
// writes only the global flag (the blocked person and the group stay listed) and clears the waiting offer; Stay out writes at once.
test('#872 setting: a restored person sees the stored choice and the not-live line; Show up asks first and changes only the global flag; Stay out writes at once; the offer is gone', async ({ browser }, testInfo) => {
  test.setTimeout(420_000);
  const a = await (await browser.newContext({ bypassCSP: true })).newPage();
  await mint(a, 'Setting Sam');
  const ownerA = (await a.evaluate(() => window.__sup.owner())) ?? '';
  await a.evaluate(([o, x]) => window.__sup.seed(o, { global: false, groups: ['family'], persons: [x] }), [ownerA, P1] as const);
  await toPassphraseStep(a);
  const vault = testInfo.outputPath('setting.svrnty');
  await finishExport(a, vault);

  const { p } = await restoreOnNewDevice(browser, vault);
  const owner = (await p.evaluate(() => window.__sup.owner())) ?? '';
  const s0 = await p.evaluate((o) => window.__sup.read(o), owner);
  expect(s0.record!.global, 'restored device starts private').toBe(true);
  expect((s0.pending as { state: string }).state, 'with an "off" waiting').toBe('ok');

  const section = await openSetting(p);
  await expect(section).toHaveAttribute('data-state', 'hidden');
  await expect(p.getByTestId('trust-map-state')).toHaveText(STATE_OFF);
  await expect(p.getByTestId('trust-map-not-live')).toHaveText(NOT_LIVE);
  await expect(p.getByTestId('trust-map-switch')).toHaveAttribute('aria-checked', 'false');
  await expect(p.getByTestId('trust-map-confirm')).toHaveCount(0);

  // Show up asks first; Cancel writes nothing.
  await p.getByTestId('trust-map-switch').click();
  await expect(p.getByTestId('trust-map-confirm')).toContainText(CONFIRM);
  await expect(p.getByTestId('trust-map-confirm-yes')).toHaveText('Show up');
  await expect(p.getByTestId('trust-map-confirm-no')).toHaveText('Cancel');
  const asked = await p.evaluate((o) => window.__sup.read(o), owner);
  expect(asked.record!.global, 'asking writes nothing').toBe(true);
  expect((asked.pending as { state: string }).state).toBe('ok');
  await p.getByTestId('trust-map-confirm-no').click();
  await expect(p.getByTestId('trust-map-confirm')).toHaveCount(0);
  const cancelled = await p.evaluate((o) => window.__sup.read(o), owner);
  expect(cancelled.record!.global, 'Cancel writes nothing').toBe(true);
  expect((cancelled.pending as { state: string }).state).toBe('ok');

  // Show up: only global changes, the offer is cleared.
  await p.getByTestId('trust-map-switch').click();
  await p.getByTestId('trust-map-confirm-yes').click();
  await expect(p.getByTestId('trust-map-state')).toHaveText(STATE_ON, { timeout: 15_000 });
  await expect(p.getByTestId('trust-map-switch')).toHaveAttribute('aria-checked', 'true');
  await expect(p.getByTestId('trust-map-write-failed')).toHaveCount(0);
  const shown = await p.evaluate((o) => window.__sup.read(o), owner);
  expect(shown.record!.global, 'global is OFF now').toBe(false);
  expect(shown.record!.persons, 'the blocked person is still listed').toEqual([P1]);
  expect(shown.record!.groups, 'and so is the group').toEqual(['family']);
  expect((shown.pending as { state: string }).state, 'the waiting offer is gone').toBe('absent');
  expect(await p.evaluate((o) => window.__sup.confirm(o), owner), 'a later restore confirmation finds nothing').toBe('no-pending');
  await expect(p.getByTestId('trust-map-not-live')).toHaveText(NOT_LIVE);

  // Stay out: no question, written at once; the list is untouched.
  await p.getByTestId('trust-map-switch').click();
  await expect(p.getByTestId('trust-map-state')).toHaveText(STATE_OFF, { timeout: 15_000 });
  await expect(p.getByTestId('trust-map-confirm')).toHaveCount(0);
  const out = await p.evaluate((o) => window.__sup.read(o), owner);
  expect(out.record!.global, 'global is ON again').toBe(true);
  expect(out.record!.persons).toEqual([P1]);
  expect(out.record!.groups).toEqual(['family']);
  expect((out.pending as { state: string }).state).toBe('absent');

  // The setting is not on the screens other people may see: not on the Identity face, not in the Galaxy.
  await p.keyboard.press('Escape');
  await p.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await expect(p.getByTestId('trust-map-settings')).toHaveCount(0);
  expect((await p.locator('body').innerText()).toLowerCase()).not.toContain('stay out of other people');
});

// A FRESH identity (never restored) has no suppression record yet: nothing writes one at creation. The panel says so in its own words (not "couldn't be read": nothing failed), offers no switch, and creates nothing.
test('#872 setting: a fresh identity (no record saved) sees the ABSENT sentence, no switch, and nothing is created', async ({ page }) => {
  test.setTimeout(240_000);
  await mint(page, 'Fresh Fay');
  const owner = (await page.evaluate(() => window.__sup.owner())) ?? '';
  const before = await page.evaluate((o) => window.__sup.read(o), owner);
  expect(before.record, 'a fresh identity has no record').toBeNull();
  const section = await openSetting(page);
  await expect(section).toHaveAttribute('data-state', 'absent');
  await expect(page.getByTestId('trust-map-absent')).toHaveText(ABSENT);
  await expect(page.getByTestId('trust-map-unreadable')).toHaveCount(0);
  await expect(page.getByTestId('trust-map-switch')).toHaveCount(0);
  await expect(page.getByTestId('trust-map-not-live')).toHaveText(NOT_LIVE);
  expect((await section.innerText()).toLowerCase()).not.toContain("couldn't be read");
  const after = await page.evaluate((o) => window.__sup.read(o), owner);
  expect(after.record, 'and nothing was created').toBeNull();
});

// A record that is saved but cannot be opened is a different state with a different sentence, and it is NEVER overwritten: the raw stored row is byte-equal before and after the panel is opened.
test('#872 setting: a saved record that cannot be read sees the UNREADABLE sentence, no switch, and the stored row is untouched', async ({ page }) => {
  test.setTimeout(240_000);
  await mint(page, 'Broken Bea');
  const owner = (await page.evaluate(() => window.__sup.owner())) ?? '';
  await page.evaluate(([o, x]) => window.__sup.seed(o, { global: true, groups: ['family'], persons: [x] }), [owner, P1] as const);
  // Corrupt the sealed row in place (valid shape, garbage ciphertext): it opens as nothing the store can understand.
  const rowKey = `suppression:${owner}`;
  const corrupt = (k: string) => page.evaluate(async (key) => {
    const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open('svrnty'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    await new Promise<void>((res, rej) => { const tx = db.transaction('settings', 'readwrite'); tx.objectStore('settings').put({ key, value: { iv: 'AAAAAAAAAAAAAAAA', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAA' } }); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
    db.close();
  }, k);
  const rawRow = (k: string) => page.evaluate(async (key) => {
    const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open('svrnty'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    const v = await new Promise<unknown>((res, rej) => { const rq = db.transaction('settings').objectStore('settings').get(key); rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error); });
    db.close();
    return JSON.stringify(v);
  }, k);
  await corrupt(rowKey);
  const before = await rawRow(rowKey);
  expect(before).toContain('AAAAAAAAAAAAAAAA');
  expect((await page.evaluate((o) => window.__sup.read(o), owner)).record, 'the record no longer reads').toBeNull();

  const section = await openSetting(page);
  await expect(section).toHaveAttribute('data-state', 'unreadable');
  await expect(page.getByTestId('trust-map-unreadable')).toHaveText(UNREADABLE);
  await expect(page.getByTestId('trust-map-absent')).toHaveCount(0);
  await expect(page.getByTestId('trust-map-switch')).toHaveCount(0);
  await expect(page.getByTestId('trust-map-not-live')).toHaveText(NOT_LIVE);
  expect(await rawRow(rowKey), 'the stored row is byte-equal: never overwritten').toBe(before);
});
