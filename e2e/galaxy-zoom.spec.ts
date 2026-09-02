import { test, expect } from '@playwright/test';

test('Galaxy zoom, fullscreen, and refresh controls', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('/');

  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Zoomer E2E');
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

  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();

  await expect(page.getByTestId('trust-map')).toBeVisible();
  await page.getByRole('button', { name: /load sample circle/i }).click();
  await expect(page.getByTestId('trust-node').first()).toBeVisible({ timeout: 20_000 });
  await page.screenshot({ path: '/opt/cursor/artifacts/galaxy_lattice_sample.png', fullPage: true });

  const svg = page.getByTestId('trust-map-svg');
  const before = await svg.getAttribute('viewBox');
  await page.getByTestId('trust-map-zoom-in').click();
  await page.getByTestId('trust-map-zoom-in').click();
  const zoomed = await svg.getAttribute('viewBox');
  expect(zoomed).not.toEqual(before);
  const beforeW = Number((before || '0 0 1 1').split(' ')[2]);
  const zoomedW = Number((zoomed || '0 0 1 1').split(' ')[2]);
  expect(zoomedW).toBeLessThan(beforeW);

  await page.getByTestId('trust-map-zoom-out').click();
  await page.getByRole('button', { name: 'Fit network' }).click();

  await page.getByTestId('trust-map-fullscreen').click();
  await expect(page.getByTestId('trust-map-shell')).toHaveAttribute('data-fullscreen', '1');
  await page.screenshot({ path: '/opt/cursor/artifacts/galaxy_fullscreen.png', fullPage: true });
  await page.keyboard.press('Escape');
  await expect(page.getByTestId('trust-map-shell')).toHaveAttribute('data-fullscreen', '0');

  await page.getByTestId('trust-map-refresh').click();
  await expect(page.getByTestId('trust-map-pull')).toBeVisible();
});
