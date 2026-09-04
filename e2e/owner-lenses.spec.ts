import { test, expect, type Page } from '@playwright/test';

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
    await expect(page.getByTestId('owner-card-studio')).toBeVisible();
    await page.getByTestId('owner-card-add-field').click();
    await page.getByPlaceholder('New lens name — Business, Festival…').fill('Festival');
    await page.getByTestId('owner-card-add-lens').click();
    await expect(page.getByRole('button', { name: /^Festival/ })).toBeVisible();
  });

  test('Contacts: sample Hypatia is classical (no fingerprint)', async ({ page }) => {
    test.setTimeout(60_000);
    await genesis(page, 'Circle Owner');
    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    // Seed is async behind the button — wait until the graph shows Refresh
    // (full roster written) before opening Contacts, or classical rows can race.
    await page.getByTestId('trust-map-load-sample').click();
    await expect(page.getByTestId('trust-map-load-sample')).toHaveText(/Refresh demo circle/i, {
      timeout: 30_000,
    });
    await page.getByRole('tab', { name: 'Contacts' }).click();

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
    await page.getByRole('tab', { name: 'Card' }).click();
    await expect(page.getByTestId('classical-no-fingerprint')).toBeVisible();
  });
});
