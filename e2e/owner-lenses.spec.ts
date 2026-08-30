import { test, expect, type Page } from '@playwright/test';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('lenses@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /begin anew/i }).click();
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

  test('Contacts: SVRNTY Ada has a fingerprint; classical Hypatia does not', async ({ page }) => {
    test.setTimeout(60_000);
    await genesis(page, 'Circle Owner');
    await page.getByRole('tab', { name: /social graph|trust map/i }).click();
    // Seed is async behind the button — wait until the graph shows Refresh
    // (full roster written) before opening Contacts, or classical rows can race.
    await page.getByTestId('trust-map-load-sample').click();
    await expect(page.getByTestId('trust-map-load-sample')).toHaveText(/Refresh demo circle/i, {
      timeout: 30_000,
    });
    await page.getByRole('tab', { name: 'Contacts' }).click();

    // Scope to master-book rows (not any other contact-row surface).
    const bookRow = (name: string) =>
      page.locator('[data-testid="contact-row"][data-master-book-row="1"]').filter({ hasText: name });

    const ada = bookRow('Ada Lovelace');
    await expect(ada).toBeVisible({ timeout: 25_000 });
    await expect(ada).toHaveAttribute('data-svrn', '1');

    const hypatia = bookRow('Hypatia');
    await expect(hypatia).toBeVisible({ timeout: 25_000 });
    await expect(hypatia).toHaveAttribute('data-svrn', '0');

    await hypatia.click();
    await page.getByRole('tab', { name: 'Card' }).click();
    await expect(page.getByTestId('classical-no-fingerprint')).toBeVisible();
    await page.keyboard.press('Escape');

    await ada.click();
    await page.getByRole('tab', { name: 'Card' }).click();
    await expect(page.getByTestId('living-fingerprint')).toBeVisible();
  });
});
