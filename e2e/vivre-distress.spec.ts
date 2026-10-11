import { test, expect } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

const ADA = 'a11a10e1ace00000000000000000000000000001';

test('Ada distress paints Ace vivre paper-edge, not a corner badge', async ({ page }) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Vivre E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 60_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 20_000,
  });
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await seedSampleGalaxy(page);

  const ada = page.locator(`[data-testid="trust-node"][data-fingerprint="${ADA}"]`);
  await expect(ada).toHaveAttribute('data-distress', 'true');
  await expect(page.getByTestId('star-ember').first()).toBeVisible();

  await ada.click({ force: true });
  const burn = page.getByTestId('vivre-burn');
  await expect(burn).toBeVisible();
  await expect(burn).toHaveAttribute('data-ace-vivre', 'edge');
  await expect(page.getByTestId('vivre-paper-bite')).toBeVisible();
  await expect(page.getByTestId('vivre-caution')).toBeVisible();

  await page.getByTestId('trust-node-detail').screenshot({
    path: '/opt/cursor/artifacts/ada_ace_vivre_card.png',
  });
  await page.screenshot({
    path: '/opt/cursor/artifacts/ada_ace_vivre_sheet.png',
    fullPage: true,
  });
});
