import { test, expect, type Page } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { RESTORE_MESSAGES } from '../src/lib/identity/restore-errors';

// What the seed (recovery-code) restore tells the owner when it fails. The screen used to decide by the error's TEXT: any message that mentioned "hash",
// "mismatch" or "seed phrase" read as a wrong recovery code, and every other error showed its OWN raw text. Real flow: mint, export a real v4 vault, restore.

test.describe.configure({ mode: 'serial', timeout: 240_000 });

const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
const RECOVER_PW = 'recover-e2e-pass-9012';

let recoveryCode = '';
let vaultPath = '';

async function mint(page: Page): Promise<string> {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Seed Errors E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  const seed = page.getByTestId('seed-phrase-display');
  await expect(seed).toBeVisible({ timeout: 60_000 });
  const code = ((await seed.textContent()) ?? '').trim();
  expect(code).toMatch(/^[0-9a-f]{8}( [0-9a-f]{8}){7}$/);
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
  return code;
}

async function exportVault(page: Page, dest: string) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const dl = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  await (await dl).saveAs(dest);
}

test.beforeAll(async ({ browser }, testInfo) => {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  recoveryCode = await mint(page);
  vaultPath = testInfo.outputPath('vault.svrnty');
  await exportVault(page, vaultPath);
  await ctx.close();
});

/** Raw text a thrower or the platform used to put on this screen. None of it may appear any more. */
const RAW = /truncated body|truncated header|unreadable \(corrupted\)|is malformed|no recovery vault|Unexpected end of JSON|Unterminated string|Not a valid \.svrnty|Invalid seed phrase|master secret|hash mismatch/i;

/** The offset where the recovery envelope starts in a v4 file: magic 8, header length 4, header, body length 4, body. */
function recoveryStart(bytes: Buffer): number {
  const headerLen = bytes.readUInt32BE(8);
  const bodyLenOffset = 8 + 4 + headerLen;
  return bodyLenOffset + 4 + bytes.readUInt32BE(bodyLenOffset);
}

const cut = (testInfo: { outputPath: (n: string) => string }, name: string, end: number): string => {
  const file = testInfo.outputPath(name);
  writeFileSync(file, readFileSync(vaultPath).subarray(0, end));
  return file;
};

/** Pick a file on a fresh device, return the page after the pick. */
async function pick(browser: import('@playwright/test').Browser, file: string): Promise<{ page: Page; close: () => Promise<void> }> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click({ timeout: 10_000 });
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
  return { page, close: () => ctx.close() };
}

/** After the pick: the recovery-code path with this code, then the button. */
async function recover(page: Page, code: string) {
  await page.getByRole('button', { name: /recover with your recovery code/i }).click({ timeout: 20_000 });
  await page.getByPlaceholder(/enter your recovery code/i).fill(code);
  await page.getByPlaceholder(/at least 12 characters/i).fill(RECOVER_PW);
  await page.getByRole('button', { name: /^recover my identity$/i }).click();
}

const body = (page: Page) => page.locator('body');

test('1. a WRONG recovery code (well formed) still says it does not match this backup', async ({ browser }) => {
  const { page, close } = await pick(browser, vaultPath);
  await recover(page, 'a'.repeat(8) + (' ' + 'b'.repeat(8)).repeat(7));
  await expect(page.getByText(RESTORE_MESSAGES.wrongRecoveryCode)).toBeVisible({ timeout: 30_000 });
  await expect(body(page)).not.toContainText(RAW);
  await close();
});

test('2. a MALFORMED recovery code says it is not in the right form, not that it does not match', async ({ browser }) => {
  const { page, close } = await pick(browser, vaultPath);
  await recover(page, 'not a code');
  await expect(page.getByText(RESTORE_MESSAGES.malformedRecoveryCode)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(RESTORE_MESSAGES.wrongRecoveryCode)).toHaveCount(0);
  await expect(body(page)).not.toContainText(RAW);
  await close();
});

test('3. a file that ends inside its body says it ends too early, in the approved sentence, and shows none of the thrower\'s text', async ({ browser }, testInfo) => {
  const file = cut(testInfo, 'cut-body.svrnty', Math.floor(readFileSync(vaultPath).length * 0.3));
  const { page, close } = await pick(browser, file);
  await recover(page, recoveryCode);
  await expect(page.getByText(RESTORE_MESSAGES.fileTruncated)).toBeVisible({ timeout: 30_000 });
  await expect(body(page)).not.toContainText(RAW);
  await close();
});

test('4. an unreadable recovery vault says part of the backup cannot be read (never "corrupted")', async ({ browser }, testInfo) => {
  const file = cut(testInfo, 'cut-recovery.svrnty', Math.floor(readFileSync(vaultPath).length * 0.95));
  const { page, close } = await pick(browser, file);
  await recover(page, recoveryCode);
  await expect(page.getByText(RESTORE_MESSAGES.backupPartUnreadable)).toBeVisible({ timeout: 30_000 });
  await expect(body(page)).not.toContainText(/corrupt/i);
  await expect(body(page)).not.toContainText(RAW);
  await close();
});

test('5. a backup made without a recovery vault says recovery codes were not set up and names the button that works', async ({ browser }, testInfo) => {
  const bytes = readFileSync(vaultPath);
  const file = cut(testInfo, 'no-recovery.svrnty', recoveryStart(bytes));
  const { page, close } = await pick(browser, file);
  await recover(page, recoveryCode);
  await expect(page.getByText(RESTORE_MESSAGES.noRecoveryVault)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole('button', { name: /^restore identity$/i })).toBeVisible(); // the button the sentence names is on this screen
  await expect(body(page)).not.toContainText(RAW);
  await close();
});

for (const bytes of [8, 76]) {
  test(`6. a file of only ${bytes} bytes (the header cut off) is refused at the PICK with "can't open this file", never the parser's own text`, async ({ browser }, testInfo) => {
    const file = cut(testInfo, `tiny-${bytes}.svrnty`, bytes);
    const { page, close } = await pick(browser, file);
    await expect(page.getByText(RESTORE_MESSAGES.unrecognizedFormat)).toBeVisible({ timeout: 15_000 });
    await expect(body(page)).not.toContainText(RAW);
    await close();
  });
}
