import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

/**
 * A blocked contact's book-card menu offers "Unblock", not "Block". The menu item's label was a fixed "Block" while its
 * click already opened the unblock confirm, so the Blocked view told the owner the wrong thing about the one action it
 * exists for (found in the row-51 prod QA). The binding assertions are the LABELS in the menu of a card reached through
 * the real Blocked view, plus the NEG: an unblocked card keeps "Block" and gains no "Unblock".
 */
async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('blocked-menu@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

// The sample "Hypatia" row (classical, no fingerprint), the same row owner-lenses.spec.ts uses.
const hypatiaRow = (page: Page) =>
  page
    .locator('[data-testid="contact-row"]')
    .filter({ hasText: 'Hypatia' })
    .filter({ hasNotText: 'Alexandria' });

async function openCardMenu(page: Page) {
  const card = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  await expect(card).toBeVisible();
  const toggle = card.getByTestId('card-actions-toggle');
  await toggle.scrollIntoViewIfNeeded();
  await toggle.click({ timeout: 10_000 });
  const menu = card.getByTestId('card-actions-toggle-menu');
  await expect(menu).toBeVisible();
  return { card, menu };
}

const VIEWPORTS: Array<[string, { width: number; height: number } | null]> = [
  ['desktop', null],
  ['phone 390x844', { width: 390, height: 844 }],
];

for (const [vpName, viewport] of VIEWPORTS) {
  test.describe(`Blocked card menu says Unblock (#772) — ${vpName}`, () => {
    test.setTimeout(120_000);
    if (viewport) test.use({ viewport });

    test('NEG: an unblocked card offers Block and no Unblock', async ({ page }) => {
      await genesis(page, 'Block Menu Neg');
      await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
      await seedSampleGalaxy(page);
      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();

      const row = hypatiaRow(page).first();
      await expect(row).toBeVisible({ timeout: 25_000 });
      await row.click();
      const { menu } = await openCardMenu(page);
      await expect(menu.getByRole('menuitem', { name: 'Block', exact: true })).toBeVisible();
      await expect(menu.getByRole('menuitem', { name: 'Unblock', exact: true })).toHaveCount(0);
    });

    test('a blocked card offers Unblock and no Block; Unblock returns the contact', async ({ page }) => {
      await genesis(page, 'Block Menu');
      await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
      await seedSampleGalaxy(page);
      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();

      // Block Hypatia through the real card menu and confirm.
      const row = hypatiaRow(page).first();
      await expect(row).toBeVisible({ timeout: 25_000 });
      await row.click();
      const first = await openCardMenu(page);
      await first.menu.getByRole('menuitem', { name: 'Block', exact: true }).click();
      const confirm = page.getByTestId('trust-action-confirm');
      await expect(confirm).toHaveAttribute('data-action-kind', 'block');
      await confirm.getByTestId('trust-action-confirm-btn').click();
      await expect(confirm).toHaveCount(0);
      await expect(hypatiaRow(page)).toHaveCount(0); // gone from the main book

      // Reach her through the Blocked view, open her card menu.
      await page.getByRole('button', { name: 'Book options' }).click();
      await page.getByRole('menuitem', { name: /view blocked contacts/i }).click();
      const blockedRow = hypatiaRow(page).first();
      await expect(blockedRow).toBeVisible({ timeout: 15_000 });
      // A row click TOGGLES its card, and the card we blocked from may still be open: pin the state (closed), then open it.
      const bookCard = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
      if (await bookCard.count()) {
        await blockedRow.click();
        await expect(bookCard).toHaveCount(0);
      }
      await blockedRow.click();
      const { menu } = await openCardMenu(page);

      await expect(menu.getByRole('menuitem', { name: 'Unblock', exact: true })).toBeVisible();
      await expect(menu.getByRole('menuitem', { name: 'Block', exact: true })).toHaveCount(0);

      // The label tells the truth: it opens the unblock confirm, and confirming returns her to the book.
      await menu.getByRole('menuitem', { name: 'Unblock', exact: true }).click();
      const confirm2 = page.getByTestId('trust-action-confirm');
      await expect(confirm2).toHaveAttribute('data-action-kind', 'unblock');
      await confirm2.getByTestId('trust-action-confirm-btn').click();
      await expect(confirm2).toHaveCount(0);
      await page.getByRole('button', { name: 'Book options' }).click();
      await page.getByRole('menuitem', { name: /hide blocked contacts/i }).click();
      await expect(hypatiaRow(page).first()).toBeVisible({ timeout: 15_000 });
    });
  });
}
