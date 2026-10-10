import { test, expect } from '@playwright/test';

/**
 * Beta-messaging copy — dogfood gap (default: NEXT_PUBLIC_SVRNTY_BETA_GATE unset).
 * Unlock/redeem must NOT render when the issuer is not provisioned.
 * Crypto redeem is unit-tested against a mocked POST; this spec is the gate-OFF chrome.
 */
test('beta redeem chrome is absent in the gate-OFF dogfood gap', async ({ page }) => {
  test.setTimeout(90_000);

  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Beta Copy E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });

  await expect(page.getByTestId('tab-beta-messaging')).toHaveCount(0);
  await expect(page.getByTestId('beta-redeem-form')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^redeem key$/i })).toHaveCount(0);
  await expect(page.getByText('Turn on beta messaging')).toHaveCount(0);
  await expect(page.getByText(/you're not allowed/i)).toHaveCount(0);
});
