import { test, expect } from '@playwright/test';
import { genesis } from './helpers/genesis';

/**
 * Queue #1 — biometric honesty: while the PRF seam is a stub, device unlock
 * must not look like a working action (pre-tap). Passphrase stays primary.
 *
 * Playwright Chromium often reports no platform authenticator; we force UVPA
 * available so the coming-soon chrome (not the live CTA) is what we assert.
 */
test('device unlock is coming-soon, not a live action, while the seam is stubbed', async ({
  page,
}) => {
  test.setTimeout(90_000);

  await page.addInitScript(() => {
    const PK = window.PublicKeyCredential as
      | (typeof PublicKeyCredential & {
          isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
        })
      | undefined;
    if (PK) {
      PK.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    }
  });

  await genesis(page, 'Honesty E2E');

  await page.getByRole('tab', { name: 'Identity' }).click();
  const settings = page.getByTestId('biometric-settings');
  await expect(settings).toBeVisible();
  await expect(settings.getByTestId('device-unlock-coming-soon')).toBeVisible();
  await expect(settings.getByTestId('biometric-enable-start')).toHaveCount(0);
  await expect(page.getByTestId('biometric-unlock-btn')).toHaveCount(0);
  await expect(settings.getByText(/device unlock is on/i)).toHaveCount(0);

  await page.getByTestId('lock-now-btn').click();
  await expect(page.getByRole('heading', { name: /welcome back/i })).toBeVisible();
  await expect(page.getByPlaceholder('Enter passphrase')).toBeVisible();
  await expect(page.getByRole('button', { name: /^UNLOCK$/i })).toBeVisible();
  await expect(page.getByTestId('device-unlock-coming-soon')).toBeVisible();
  await expect(page.getByTestId('biometric-unlock-btn')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /unlock with device/i })).toHaveCount(0);
  await expect(page.getByTestId('new-identity-btn')).toHaveCount(0);
  await expect(page.getByTestId('open-another-vault')).toBeVisible();
  await expect(page.getByTestId('switch-identity')).toBeVisible();
});
