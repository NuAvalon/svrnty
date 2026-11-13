import { test, expect, type Page } from '@playwright/test';

/**
 * The Delivery receipts setting after a REAL restore, through the screens (no planted marker): mint an identity, export an encrypted vault, restore it
 * in a fresh browser context (an empty IndexedDB = a new device) by each of the two restore paths, then open Settings (Identity tab) and read the panel.
 * Recovery-code restore: the recovery code does not carry the owner's choice, so the panel must be asking (data-state="ask"), not already "on": no receipts
 * go out until they answer. Vault-passphrase restore: the passphrase-authenticated vault DOES carry the choice (importVaultContentsReport), so it comes back
 * as it was; Off is set before the export so a restored "off" can only have come from the vault (a default would be "on").
 * The mint/export/restore steps are the ones recovery-canonical-persist.spec.ts drives; this file asserts the Delivery side of them.
 */
const APP = 'http://localhost:3000/';
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
const RECOVER_PW = 'recover-e2e-pass-9012';

async function mint(page: Page): Promise<{ recoveryCode: string }> {
  await page.goto(APP);
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Delivery Restore');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  const seed = page.getByTestId('seed-phrase-display');
  await expect(seed).toBeVisible({ timeout: 45_000 });
  const recoveryCode = ((await seed.textContent()) ?? '').trim();
  expect(recoveryCode).toMatch(/^[0-9a-f]{8}( [0-9a-f]{8}){7}$/);
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
  return { recoveryCode };
}

async function exportVault(page: Page, dest: string): Promise<string> {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  const download = await downloadPromise;
  await download.saveAs(dest);
  return dest;
}

async function openRestoreWithFile(page: Page, vaultPath: string) {
  await page.goto(APP);
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('input[accept=".svrnty,.json"]', vaultPath);
}

async function expectAsk(page: Page) {
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  const panel = page.getByTestId('delivery-settings');
  await expect(panel).toBeVisible({ timeout: 15_000 });
  await expect(panel).toHaveAttribute('data-state', 'ask');
  await expect(page.getByTestId('delivery-restore-ask')).toBeVisible();
  await expect(page.getByTestId('delivery-upgrade-notice')).toHaveCount(0);
  await expect(page.getByTestId('delivery-on')).toHaveCount(0); // no switch until the question is answered
}

test.describe('Delivery receipts after a real restore', () => {
  test('control: a freshly minted identity is not asked (it starts on, with the upgrade notice)', async ({ page }) => {
    test.setTimeout(120_000);
    await mint(page);
    await page.getByRole('tab', { name: 'Identity', exact: true }).click();
    await expect(page.getByTestId('delivery-settings')).toHaveAttribute('data-state', 'on', { timeout: 15_000 });
    await expect(page.getByTestId('delivery-restore-ask')).toHaveCount(0);
  });

  test('vault-passphrase restore keeps the choice the vault carried (Off stays Off), and asks nothing', async ({ page, browser }, testInfo) => {
    test.setTimeout(150_000);
    await mint(page);
    await page.getByRole('tab', { name: 'Identity', exact: true }).click();
    await page.getByTestId('delivery-off').click();
    await expect(page.getByTestId('delivery-settings')).toHaveAttribute('data-state', 'off');
    const vaultPath = await exportVault(page, testInfo.outputPath('vault.svrnty'));
    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    await openRestoreWithFile(p, vaultPath);
    await p.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
    await p.getByRole('button', { name: /^restore identity$/i }).click();
    await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
    await p.getByRole('tab', { name: 'Identity', exact: true }).click();
    const panel = p.getByTestId('delivery-settings');
    await expect(panel).toBeVisible({ timeout: 15_000 });
    await expect(panel).toHaveAttribute('data-state', 'off');
    await expect(p.getByTestId('delivery-restore-ask')).toHaveCount(0);
    await expect(p.getByTestId('delivery-upgrade-notice')).toHaveCount(0);
    await ctx.close();
  });

  test('recovery-code (seed) restore: the owner is asked, and answering No turns it off', async ({ page, browser }, testInfo) => {
    test.setTimeout(150_000);
    const { recoveryCode } = await mint(page);
    const vaultPath = await exportVault(page, testInfo.outputPath('vault.svrnty'));
    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    await openRestoreWithFile(p, vaultPath);
    await p.getByRole('button', { name: /recover with your recovery code/i }).click();
    await p.getByPlaceholder(/enter your recovery code/i).fill(recoveryCode);
    await p.getByPlaceholder(/at least 12 characters/i).fill(RECOVER_PW);
    await p.getByRole('button', { name: /^recover my identity$/i }).click();
    await expect(p.getByRole('heading', { name: /your identity is back/i })).toBeVisible({ timeout: 30_000 });
    await p.getByRole('button', { name: /^continue$/i }).click();
    await expect(p.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
    await expectAsk(p);
    await p.getByTestId('delivery-restore-no').click();
    await expect(p.getByTestId('delivery-settings')).toHaveAttribute('data-state', 'off');
    await ctx.close();
  });
});
