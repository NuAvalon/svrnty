import { test, expect, type Page } from '@playwright/test';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('consent-legend@example.test');
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

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 20_000,
  });
}

test('Galaxy consent legend states disclosures, not observations — never infers', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await genesis(page, 'Consent Legend E2E');

  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  const legend = page.getByTestId('trust-map-consent-legend');
  await expect(legend).toBeVisible();
  await expect(legend).toContainText(/Every visible line consented — none inferred/);
  const body = page.getByTestId('hint-body-galaxy-consent');
  if (!(await body.isVisible())) {
    await page.getByTestId('hint-toggle-galaxy-consent').click();
  }
  await expect(body).toBeVisible();
  await expect(legend).toContainText(/disclosures, not observations/i);
  await expect(legend).toContainText(/never infers who knows whom/i);
  await page.getByTestId('hint-toggle-galaxy-consent').click();
  await expect(body).toHaveCount(0);
  await expect(legend).toContainText(/Every visible line consented — none inferred/);
});
