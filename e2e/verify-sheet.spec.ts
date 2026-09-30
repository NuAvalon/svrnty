import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('verify-sheet@example.test');
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

test('Galaxy Verify — guided compare, mismatch fails loud, other-channel match records privately', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await genesis(page, 'Verify Sheet E2E');

  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await expect(page.getByTestId('trust-map')).toBeVisible();
  await seedSampleGalaxy(page);
  await expect(page.getByTestId('trust-node').first()).toBeVisible({ timeout: 20_000 });

  const known = page.locator(
    '[data-testid="trust-node"][data-trust-state="known"][data-verified="false"][data-ignite="false"]',
  ).first();
  await expect(known).toBeVisible({ timeout: 15_000 });
  const storedFp = (await known.getAttribute('data-fingerprint')) || '';
  expect(storedFp.length).toBeGreaterThan(8);
  await known.click();

  await expect(page.getByTestId('trust-node-detail')).toBeVisible();
  await page.getByTestId('galaxy-verify').click();

  const sheet = page.getByTestId('verify-sheet');
  await expect(sheet).toBeVisible();
  const grouped = (await sheet.getByTestId('verify-fingerprint').innerText()).trim();
  const hex = (s: string) => s.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
  expect(hex(grouped)).toBe(hex(storedFp));
  await expect(sheet.getByText(/anyone can use my name/i)).toBeVisible();
  await expect(sheet.getByText(/only you see whom you've verified/i)).toBeVisible();

  await sheet.getByTestId('verify-path-other-channel').click();
  await sheet.getByTestId('verify-paste').fill('f'.repeat(Math.max(hex(storedFp).length, 16)));
  await expect(sheet.getByTestId('verify-mismatch')).toContainText(/do not verify/i);
  await expect(sheet.getByTestId('verify-confirm')).toBeDisabled();

  await sheet.getByTestId('verify-paste').fill(grouped);
  await expect(sheet.getByTestId('verify-mismatch')).toHaveCount(0);
  await sheet.getByTestId('verify-code-matches').check();
  await sheet.getByTestId('verify-confirm').click();

  await expect(sheet.getByTestId('verify-saved')).toContainText(/you verified this key on this device/i);
  await sheet.getByTestId('verify-close').click();
  await expect(sheet).toHaveCount(0);

  await expect(
    page.locator(`[data-testid="trust-node"][data-fingerprint="${storedFp}"]`),
  ).toHaveAttribute('data-verified', 'true');
});
