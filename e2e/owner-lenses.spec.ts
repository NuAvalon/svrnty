import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('lenses@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts' })).toBeVisible({ timeout: 15_000 });
}

test.describe('Owner lenses + living vs classical sample circle', () => {
  test('Identity: add a field and a named lens', async ({ page }) => {
    await genesis(page, 'Lens Owner');
    await page.getByRole('tab', { name: 'Identity' }).click();
    await page.getByTestId('identity-vault-toggle').click();
    await expect(page.getByTestId('owner-card-studio')).toBeVisible();
    await page.getByTestId('owner-card-add-field').click();
    await page.getByPlaceholder('New lens name — Business, Festival…').fill('Festival');
    await page.getByTestId('owner-card-add-lens').click();
    await expect(page.getByRole('button', { name: /^Festival/ }).first()).toBeVisible();
  });

  test('each lens has its own card; Grow picks a face', async ({ page }) => {
    test.setTimeout(90_000);
    await genesis(page, 'Peter Card');
    await page.getByRole('tab', { name: 'Identity' }).click();

    await expect(page.getByTestId('identity-card-name')).toHaveText('Peter Card');
    await expect(page.getByTestId('identity-lens-picker')).toBeVisible();

    await page.getByTestId('identity-vault-toggle').click();
    await expect(page.getByTestId('owner-card-studio')).toBeVisible();

    await page.getByTestId('owner-card-add-kind').selectOption('instagram');
    await page.getByTestId('owner-card-add-field').click();
    const instagram = page.getByPlaceholder('Instagram').last();
    await instagram.fill('@archie.fest');

    await page.getByPlaceholder('New lens name — Business, Festival…').fill('Festival');
    await page.getByTestId('owner-card-add-lens').click();
    await expect(page.getByTestId('studio-lens-picker-chip').filter({ hasText: 'Festival' })).toBeVisible();

    await page.getByTestId('owner-lens-display-name').fill('Archie');
    await page.getByTestId('owner-lens-handle').fill('archie.fest');
    await page.getByTestId('owner-lens-note').fill('festival face');
    await page
      .getByTestId('owner-card-studio')
      .locator('label')
      .filter({ hasText: 'Instagram' })
      .getByRole('checkbox')
      .check();

    await page.getByTestId('identity-vault-toggle').click();

    await page.getByTestId('identity-lens-picker-chip').filter({ hasText: 'Festival' }).click();
    await expect(page.getByTestId('identity-card-name')).toHaveText('Archie');
    await expect(page.getByTestId('identity-card-face')).toHaveAttribute('data-lens-name', 'Festival');
    await expect(page.getByTestId('identity-card-note')).toHaveText('festival face');
    await expect(page.getByTestId('identity-card-methods')).toContainText('Instagram');
    await expect(page.getByTestId('identity-card-methods')).not.toContainText('Email');

    await page.getByTestId('identity-lens-picker-chip').filter({ hasText: 'Everyone' }).click();
    await expect(page.getByTestId('identity-card-name')).toHaveText('Peter Card');
    await expect(page.getByTestId('identity-card-methods')).toContainText('Email');
    await expect(page.getByTestId('identity-card-methods')).toContainText('Instagram');

    await page.getByTestId('nav-grow').click();
    const grow = page.getByTestId('grow-surface');
    await expect(grow).toBeVisible();
    await expect(grow.getByTestId('grow-lens-picker')).toBeVisible();
    await grow.getByTestId('grow-lens-picker-chip').filter({ hasText: 'Festival' }).click();
    await expect(grow.getByTestId('grow-lens-face-name')).toHaveText('Archie');
    await expect(grow.getByTestId('grow-lens-face')).toContainText('festival face');
    await expect(grow.getByTestId('grow-lens-face')).toContainText('@archie.fest');
  });

  test('Contacts: sample Hypatia is classical (no fingerprint)', async ({ page }) => {
    test.setTimeout(60_000);
    await genesis(page, 'Circle Owner');
    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    await seedSampleGalaxy(page);
    await page.getByRole('tab', { name: 'Contacts' }).click();

    const scroller = page.getByTestId('contacts-book-scroll');
    await expect(scroller).toBeVisible();
    await expect
      .poll(async () => scroller.evaluate((el) => getComputedStyle(el).overflowY))
      .toMatch(/auto|scroll/);

    const bookRow = scroller.locator('[data-testid="contact-row"][data-master-book-row="1"]');
    await expect(bookRow.first()).toContainText('Ada');
    await page.getByTestId('contacts-book-sort').selectOption('name-desc');
    await expect(bookRow.first()).toContainText('Nikola');
    await page.getByTestId('contacts-book-sort').selectOption('name-asc');

    // Scope to master-book rows (not any other contact-row surface).
    // Today's sample-circle seed writes public_key:'' for every demo row, so after
    // #83 (fingerprint only with a bound key) Ada is classical too. Living keys
    // exist in SAMPLE_SVRNTY_PEERS but are not wired into seedSampleCircle
    // (CODEOWNERS /src/lib/trust/ — fleet). Assert the classical Hypatia card.
    const hypatia = page
      .locator('[data-testid="contact-row"][data-master-book-row="1"][data-svrn="0"]')
      .filter({ hasText: 'Hypatia' })
      .filter({ hasNotText: 'Alexandria' });
    await expect(hypatia).toBeVisible({ timeout: 25_000 });
    await expect(hypatia).toHaveAttribute('data-svrn', '0');

    await hypatia.click();
    await expect(page.getByTestId('contact-action-card')).toBeVisible();
    await page.getByTestId('star-sheet-expand').click();
    await expect(page.getByTestId('classical-no-fingerprint')).toBeVisible();
  });
});
