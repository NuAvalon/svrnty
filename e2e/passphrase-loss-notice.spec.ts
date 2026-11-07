import { test, expect, type Page } from '@playwright/test';
import path from 'node:path';
import { PASSPHRASE_LOSS_NOTICE_BACKUP, PASSPHRASE_LOSS_NOTICE_CONTACTS } from '../src/lib/identity/passphrase-loss-notice';

// The notice for people whose contacts or backup went missing after a passphrase change or a restore. It is shown in two places and nowhere else:
// at the top of the Contacts card while the book is empty, and in the backup dialog. A new user, with contacts or in a search, must not see the contacts one.
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

// On a phone the notice has to be on the FIRST screen, unscrolled: its whole job is to be SEEN before someone clears their data.
// The page can be left scrolled after genesis (scrollY 24-33), which once hid a clipped last line, so each test scrolls to 0 and asserts it.
for (const vp of [{ width: 390, height: 844 }, { width: 375, height: 667 }]) {
  test.describe(`on a phone ${vp.width}x${vp.height}`, () => {
    test.use({ viewport: vp });
    test('the whole notice is on the first screen at scrollY 0, above the import buttons', async ({ page }) => {
      test.setTimeout(150_000);
      await createIdentity(page);
      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
      const notice = page.getByTestId('passphrase-loss-notice');
      await expect(notice).toHaveText(PASSPHRASE_LOSS_NOTICE_CONTACTS);
      await page.evaluate(() => window.scrollTo(0, 0));
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
      if (process.env.NOTICE_SHOT_DIR) await page.screenshot({ path: `${process.env.NOTICE_SHOT_DIR}/notice_${vp.width}x${vp.height}.png` }); // before the assertions, so a failure still leaves the picture
      const innerHeight = await page.evaluate(() => window.innerHeight);
      const n = await notice.boundingBox();
      const btn = await page.getByTestId('import-contacts-trigger').boundingBox();
      expect(n && n.y >= 0 && n.y + n.height <= innerHeight, `notice ${JSON.stringify(n)} must lie inside the first screen (innerHeight ${innerHeight}) at scrollY 0`).toBeTruthy();
      expect(n && btn && n.y + n.height <= btn.y + 1, `notice ${JSON.stringify(n)} must end above the import buttons ${JSON.stringify(btn)}`).toBeTruthy();
    });
  });
}

test('the notice appears under "No contacts yet" and in the backup dialog, and not where it does not belong', async ({ page }) => {
  test.setTimeout(150_000);
  await createIdentity(page);

  // 1. An empty book: "No contacts yet", with the notice under it.
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(page.getByText('No contacts yet', { exact: true })).toBeVisible();
  await expect(page.getByTestId('passphrase-loss-notice')).toHaveText(PASSPHRASE_LOSS_NOTICE_CONTACTS);

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
