import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

/**
 * PR#221 regression — the remove-contact confirm had TWO stacked occlusion layers:
 * (a) it rendered INSIDE ContactManagement's backdrop-filter card, a containing
 *     block for fixed descendants, so the z-80 overlay painted *behind* the
 *     Radix z-50 detail dialog → fixed by portaling to document.body;
 * (b) even portaled, Radix's modal scroll-lock sets pointer-events:none on body
 *     and re-enables only its own portal shard, leaving the confirm inert →
 *     fixed by pointerEvents:'auto' on the overlay.
 *
 * The binding assertion is the CLICK, not just visibility: layer (b) passes every
 * visual check while every button is dead — Playwright's actionability hit-test
 * is the only assert that catches it.
 */
async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('remove-confirm@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

test.describe('Remove-contact confirm — portals above the detail dialog (PR#221)', () => {
  test.setTimeout(90_000);

  test('confirm renders above and is clickable; remove lands', async ({ page }) => {
    await genesis(page, 'Remove Confirm');
    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    await seedSampleGalaxy(page);
    await page.getByRole('tab', { name: 'Contacts', exact: true }).click();

    const alanRow = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Alan Turing' });
    await expect(alanRow).toBeVisible();
    await alanRow.click();

    // Detail dialog opens; Remove lives under the Actions overflow menu. Both
    // dialogs stay mounted — the regression painted the confirm *behind* this one.
    await page.getByRole('button', { name: /^actions$/i }).click();
    await page.getByRole('menuitem', { name: /remove/i }).click();
    const confirm = page.getByTestId('trust-action-confirm');
    await expect(confirm).toBeVisible();
    await expect(confirm).toHaveAttribute('data-action-kind', 'remove');

    // THE REGRESSION ASSERTION — this click was impossible pre-portal (the Radix
    // overlay won the hit-test at the button's center).
    await confirm.getByTestId('trust-action-confirm-btn').click();

    await expect(confirm).toHaveCount(0);
    await expect(
      page.locator('[data-testid="contact-row"]').filter({ hasText: 'Alan Turing' }),
    ).toHaveCount(0);
  });

  test('cancel keeps the contact (overlay path also was occluded)', async ({ page }) => {
    await genesis(page, 'Remove Cancel');
    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    await seedSampleGalaxy(page);
    await page.getByRole('tab', { name: 'Contacts', exact: true }).click();

    const alanRow = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Alan Turing' });
    await expect(alanRow).toBeVisible();
    await alanRow.click();
    await page.getByRole('button', { name: /^actions$/i }).click();
    await page.getByRole('menuitem', { name: /remove/i }).click();

    const confirm = page.getByTestId('trust-action-confirm');
    await expect(confirm).toBeVisible();
    await confirm.getByTestId('trust-action-cancel').click();

    await expect(confirm).toHaveCount(0);
    await expect(
      page.locator('[data-testid="contact-row"]').filter({ hasText: 'Alan Turing' }),
    ).toBeVisible();
  });
});
