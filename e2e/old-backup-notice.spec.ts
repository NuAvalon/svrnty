import { test, expect, type Browser, type Page } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { downgradeToOldFormat } from './old-backup-helper';
import { OLD_BACKUP_MAKE_NEW, OLD_BACKUP_NOT_NOW, OLD_BACKUP_NOTICE, OLD_BACKUP_PRE_RESTORE_HINT } from '../src/components/export/old-backup-copy';

// A person who restores an OLDER-FORMAT backup file is shown, on their Identity tab, that they should make a new backup (a new one can also be restored with the recovery code).
// The restore screen that used to hold this notice is gone the moment the identity is set, so the notice never reached anyone; this spec drives the real screens end to end:
//   restore the old file (the screen's own hint is the reviewed sentence) -> the Identity tab shows the notice -> Not now hides it for the session (a tab switch keeps it hidden)
//   -> a reload and unlock bring it back -> Make a new backup opens the real Full Backup flow, and a finished export clears it (at once, and after a reload)
//   -> a fresh device restoring that NEW backup is not shown it (the marker is never inside a backup).
// And the other side: an old file whose body carries no recovery vault leaves NO notice (a new backup from that device could not be restored with a recovery code).

test.use({ bypassCSP: true, actionTimeout: 30_000 });

const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';

async function mint(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Old Backup Olga');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 45_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

// The finished dialog has two Close buttons (the footer's and the corner X); either closes it.
const dialogClose = (page: Page) => page.getByTestId('vault-export-dialog').getByRole('button', { name: /^close$/i }).first();

/** Drives Full Backup from its Identity-tab entry (opener = the Identity tab's own button) or from an already open dialog (opener = null). */
async function exportThroughDialog(page: Page, unlockPw: string, exportPw: string, dest: string | null, opener: 'menu' | null) {
  if (opener === 'menu') {
    await page.getByRole('tab', { name: 'Identity', exact: true }).click();
    await page.getByTestId('card-actions-toggle').click();
    await page.getByTestId('full-backup-open').click();
  }
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(unlockPw);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByTestId('vault-export-passphrase')).toBeVisible({ timeout: 15_000 });
  await page.getByTestId('vault-export-passphrase').fill(exportPw);
  await page.getByTestId('vault-export-confirm').fill(exportPw);
  const dl = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  const d = await dl;
  if (dest) await d.saveAs(dest);
  await expect(dialogClose(page)).toBeVisible({ timeout: 30_000 });
}

async function makeOldFile(browser: Browser, dest: string, opts?: { dropRecovery?: boolean }): Promise<void> {
  const ctx = await browser.newContext({ bypassCSP: true });
  const a = await ctx.newPage();
  await mint(a);
  const v4 = dest + '.v4';
  await exportThroughDialog(a, UNLOCK_PW, EXPORT_PW, v4, 'menu');
  const buf = readFileSync(v4);
  const old = await downgradeToOldFormat(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer, EXPORT_PW, opts);
  writeFileSync(dest, Buffer.from(old));
  await ctx.close();
}

async function openRestoreScreen(page: Page, file: string): Promise<void> {
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', file);
}

async function restoreByPassphrase(page: Page): Promise<void> {
  await page.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
  await page.getByRole('button', { name: /^restore identity$/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 60_000 });
}

async function openIdentityTab(page: Page): Promise<void> {
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  await expect(page.getByTestId('card-actions-toggle')).toBeVisible({ timeout: 15_000 });
}

/** After a reload the app is locked; the everyday unlock passphrase after a passphrase restore is the vault passphrase. */
async function reloadAndUnlock(page: Page): Promise<void> {
  await page.reload();
  await page.getByPlaceholder('Enter passphrase').fill(EXPORT_PW);
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 60_000 });
}

/** The notice's absence is only meaningful after its asynchronous look has had time to finish; the Identity card being up is the sign the tab is mounted. */
async function expectNoNotice(page: Page): Promise<void> {
  await expect(page.getByTestId('card-actions-toggle')).toBeVisible();
  await page.waitForTimeout(2_000);
  await expect(page.getByTestId('old-backup-notice')).toHaveCount(0);
}

for (const [label, viewport] of [['desktop', { width: 1280, height: 800 }], ['phone390', { width: 390, height: 844 }]] as const) {
  test.describe(label, () => {
    test.use({ viewport });

    test('restoring an older-format backup: the notice shows on the Identity tab, Not now lasts the session, a finished new backup clears it, and the new backup does not carry it', async ({ browser }, testInfo) => {
      test.setTimeout(900_000);
      const oldFile = testInfo.outputPath('old.svrnty');
      await makeOldFile(browser, oldFile);

      const ctx = await browser.newContext({ bypassCSP: true, viewport });
      const p = await ctx.newPage();
      await openRestoreScreen(p, oldFile);
      // BEFORE the restore: the screen's own hint is the reviewed sentence pair.
      await expect(p.getByTestId('old-backup-pre-restore-hint')).toHaveText(OLD_BACKUP_PRE_RESTORE_HINT, { timeout: 60_000 });
      await restoreByPassphrase(p);

      // AFTER the restore: the Identity tab says so, in the reviewed words, with the two buttons, inside the screen at this width.
      await openIdentityTab(p);
      const notice = p.getByTestId('old-backup-notice');
      await expect(notice).toBeVisible({ timeout: 15_000 });
      await expect(p.getByTestId('old-backup-text')).toHaveText(OLD_BACKUP_NOTICE);
      await expect(p.getByTestId('old-backup-make')).toHaveText(OLD_BACKUP_MAKE_NEW);
      await expect(p.getByTestId('old-backup-not-now')).toHaveText(OLD_BACKUP_NOT_NOW);
      await notice.scrollIntoViewIfNeeded();
      const box = (await notice.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
      await p.screenshot({ path: testInfo.outputPath(`notice_${label}.png`) });

      // Not now: hidden for the session, and a tab switch does not bring it back.
      await p.getByTestId('old-backup-not-now').click();
      await expect(notice).toHaveCount(0);
      await p.getByRole('tab', { name: 'Contacts', exact: true }).click();
      await openIdentityTab(p);
      await expectNoNotice(p);

      // A reload and unlock is a new session: the notice is back (Not now never touched the stored marker).
      await reloadAndUnlock(p);
      await openIdentityTab(p);
      await expect(p.getByTestId('old-backup-notice')).toBeVisible({ timeout: 15_000 });

      // Make a new backup opens the real Full Backup flow; finishing it clears the notice at once.
      await p.getByTestId('old-backup-make').click();
      const newFile = testInfo.outputPath('new.svrnty');
      await exportThroughDialog(p, EXPORT_PW, EXPORT_PW, newFile, null);
      await dialogClose(p).click();
      await expectNoNotice(p);

      // ...and it stays cleared after a reload.
      await reloadAndUnlock(p);
      await openIdentityTab(p);
      await expectNoNotice(p);
      await ctx.close();

      // A fresh device restoring the NEW backup is not shown the notice: the marker is never inside a backup file.
      const ctx2 = await browser.newContext({ bypassCSP: true, viewport });
      const c = await ctx2.newPage();
      await openRestoreScreen(c, newFile);
      await expect(c.getByTestId('old-backup-pre-restore-hint')).toHaveCount(0);
      await restoreByPassphrase(c);
      await openIdentityTab(c);
      await expectNoNotice(c);
      await ctx2.close();
    });

    test('an older-format backup with NO recovery vault in it: the restore screen still warns, and no notice is left (a new backup from that device could not promise a recovery code)', async ({ browser }, testInfo) => {
      test.setTimeout(600_000);
      const oldFile = testInfo.outputPath('old_norecovery.svrnty');
      await makeOldFile(browser, oldFile, { dropRecovery: true });

      const ctx = await browser.newContext({ bypassCSP: true, viewport });
      const p = await ctx.newPage();
      await openRestoreScreen(p, oldFile);
      await expect(p.getByTestId('old-backup-pre-restore-hint')).toHaveText(OLD_BACKUP_PRE_RESTORE_HINT, { timeout: 60_000 });
      await restoreByPassphrase(p);
      await openIdentityTab(p);
      await expectNoNotice(p);
      await ctx.close();
    });
  });
}
