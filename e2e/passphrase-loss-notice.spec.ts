import { test, expect, type Page } from '@playwright/test';
import path from 'node:path';
import { PASSPHRASE_LOSS_NOTICE_BACKUP, PASSPHRASE_LOSS_NOTICE_CONTACTS } from '../src/lib/identity/passphrase-loss-notice';

// The notice for people whose contacts or backup went missing after a passphrase change or a restore. It is shown in two places and nowhere else:
// under "No contacts yet" on the Contacts screen, and in the backup dialog. A new user, with contacts or in a search, must not see the contacts one.
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const VCF = path.join(__dirname, 'fixtures', 'contacts.vcf'); // 3 contacts

async function createIdentity(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Notice E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 45_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

// On a phone the notice has to be on the first screen, above the "Import a VCF" hint: its whole job is to be SEEN before someone clears their data.
test.describe('on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test('the notice is fully on the first screen, above the import hint', async ({ page }) => {
    test.setTimeout(150_000);
    await createIdentity(page);
    await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
    const notice = page.getByTestId('passphrase-loss-notice');
    await expect(notice).toHaveText(PASSPHRASE_LOSS_NOTICE_CONTACTS);
    if (process.env.NOTICE_SHOT) await page.screenshot({ path: process.env.NOTICE_SHOT }); // before the assertion, so a failure still leaves the picture
    await expect(page.getByTestId('empty-book-icon')).toBeHidden(); // the icon is what made room; on a phone it is dropped for the empty book
    await expect(notice).toBeInViewport({ ratio: 1, timeout: 10_000 });
    const hint = page.getByText('Import a VCF or add someone to start your master book', { exact: true });
    await expect(hint).toBeVisible();
    const n = await notice.boundingBox();
    const h = await hint.boundingBox();
    expect(n && h && n.y + n.height <= h.y + 1, `notice ${JSON.stringify(n)} must end above the hint ${JSON.stringify(h)}`).toBeTruthy();
  });
});

test('the notice appears under "No contacts yet" and in the backup dialog, and not where it does not belong', async ({ page }) => {
  test.setTimeout(150_000);
  await createIdentity(page);

  // 1. An empty book: "No contacts yet", with the notice under it.
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(page.getByText('No contacts yet', { exact: true })).toBeVisible();
  await expect(page.getByTestId('passphrase-loss-notice')).toHaveText(PASSPHRASE_LOSS_NOTICE_CONTACTS);
  await expect(page.getByTestId('empty-book-icon')).toBeVisible(); // desktop keeps its icon

  // 2. A search with no match is a different state: no notice.
  await page.getByPlaceholder(/search/i).first().fill('zzzz-no-such-contact');
  await expect(page.getByText('No matching contacts', { exact: true })).toBeVisible();
  await expect(page.getByTestId('passphrase-loss-notice')).toHaveCount(0);
  await page.getByPlaceholder(/search/i).first().fill('');

  // 3. With contacts there is no empty state, so no notice.
  await page.getByTestId('import-contacts-trigger').click();
  await page.getByTestId('vcf-input').setInputFiles(VCF);
  await page.getByTestId('import-confirm').click();
  await expect(page.getByTestId('import-done')).toBeVisible();
  await page.getByRole('button', { name: /^Done$/ }).click();
  await expect(page.getByTestId('contact-row').first()).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('passphrase-loss-notice')).toHaveCount(0);

  // 4. The backup dialog carries its own notice.
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByTestId('vault-export-dialog')).toBeVisible();
  await expect(page.getByTestId('passphrase-loss-notice-backup')).toHaveText(PASSPHRASE_LOSS_NOTICE_BACKUP);
});
