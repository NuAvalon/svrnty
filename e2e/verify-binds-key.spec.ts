// Trust needs a Verify stamp for the contact's current key, on the user path in a real browser (desktop and a 390 px phone):
//  1. the trusted demo contacts exist after the seed (the store's create gate accepted their stamps),
//  2. a Trust tap on a contact that is not verified opens Verify and does NOT trust it,
//  3. Verify works on a keyless demo row (the store drops its real fingerprint field; its stand-in is the key),
//  4. after Verify, Trust works.
import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy, SAMPLE_TESLA_FP } from './helpers/seed-sample-galaxy';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('verify-binds-key@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  const welcome = page.getByRole('heading', { name: /welcome back/i });
  try {
    await welcome.waitFor({ state: 'visible', timeout: 3_000 });
    await page.getByPlaceholder('Enter passphrase').fill('e2e-passphrase-1234');
    await page.getByRole('button', { name: /^UNLOCK$/i }).click();
  } catch {
    /* already unlocked */
  }
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

const VIEWPORTS: Array<[string, { width: number; height: number } | null]> = [
  ['desktop', null],
  ['phone 390x844', { width: 390, height: 844 }],
];

for (const [vpName, viewport] of VIEWPORTS) {
  test.describe(`verify binds the key: ${vpName}`, () => {
    if (viewport) test.use({ viewport });

    test('the trusted demo contacts exist; a Trust tap on an unverified contact opens Verify and does not trust; Verify then Trust works on a keyless demo row', async ({ page }) => {
      test.setTimeout(120_000);
      await genesis(page, 'Verify Binds Key E2E');
      await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
      await expect(page.getByTestId('trust-map')).toBeVisible();
      await seedSampleGalaxy(page);

      // 1. the seed created trusted contacts through the store's real create gate
      const trusted = page.locator('[data-testid="trust-node"][data-bond-state="trust-sent"]');
      await expect(trusted.first()).toBeVisible({ timeout: 20_000 });
      expect(await trusted.count(), 'trusted demo contacts were created (their stamps passed the create gate)').toBeGreaterThan(0);

      // 2. a Trust tap on a contact that is not verified opens Verify and trusts nothing
      const tesla = page.locator(`[data-testid="trust-node"][data-fingerprint="${SAMPLE_TESLA_FP}"]`);
      await expect(tesla).toHaveAttribute('data-verified', 'false', { timeout: 15_000 });
      await expect(tesla).not.toHaveAttribute('data-bond-state', 'trust-sent');
      await tesla.click();
      await expect(page.getByTestId('trust-node-detail')).toBeVisible();
      await page.getByTestId('card-actions-toggle').click();
      await page.getByTestId('galaxy-trust').click();
      const sheet = page.getByTestId('verify-sheet');
      await expect(sheet, 'Trust on an unverified contact opens Verify').toBeVisible();
      await page.keyboard.press('Escape'); // dismissed without confirming (verify-close only exists after a save)
      await expect(sheet).toHaveCount(0);
      await expect(tesla, 'closing Verify trusted nothing').not.toHaveAttribute('data-bond-state', 'trust-sent');
      await expect(tesla).toHaveAttribute('data-verified', 'false');

      // 3. Verify works on a keyless demo row
      await tesla.click();
      await page.getByTestId('card-actions-toggle').click();
      await page.getByTestId('galaxy-trust').click();
      await expect(sheet).toBeVisible();
      const grouped = (await sheet.getByTestId('verify-fingerprint').innerText()).trim();
      await sheet.getByTestId('verify-path-other-channel').click();
      await sheet.getByTestId('verify-paste').fill(grouped);
      await sheet.getByTestId('verify-code-matches').check();
      await sheet.getByTestId('verify-confirm').click();
      await expect(sheet.getByTestId('verify-saved')).toBeVisible({ timeout: 15_000 });
      await sheet.getByTestId('verify-close').click();
      await expect(sheet).toHaveCount(0);
      await expect(tesla, 'the stamp counts for this contact\'s own key').toHaveAttribute('data-verified', 'true', { timeout: 15_000 });

      // 4. after Verify, the Trust the owner asked for goes on to its own confirmation, and confirming it trusts the contact
      await expect(page.getByTestId('trust-action-confirm'), 'Verify then Trust: the confirmation opens').toBeVisible({ timeout: 15_000 });
      await expect(tesla, 'nothing is trusted before the confirmation').not.toHaveAttribute('data-bond-state', 'trust-sent');
      await page.getByTestId('trust-action-confirm-btn').click();
      await expect(tesla).toHaveAttribute('data-bond-state', 'trust-sent', { timeout: 15_000 });
    });
  });
}
