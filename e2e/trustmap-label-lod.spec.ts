import { test, expect, type Page } from '@playwright/test';
import path from 'path';

const ART = '/opt/cursor/artifacts/screenshots';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('lod@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /begin anew/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts' })).toBeVisible({ timeout: 15_000 });
}

test('Trust Map label LOD + dense sample', async ({ page }) => {
  test.setTimeout(120_000);
  await genesis(page, 'LOD Owner');
  await page.getByRole('tab', { name: /social graph|trust map/i }).click();
  await page.getByTestId('trust-map-load-sample').click();
  await expect(page.getByTestId('trust-map-load-sample')).toHaveText(/Refresh demo circle/i, {
    timeout: 60_000,
  });
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-fit.png'), fullPage: true });

  // Zoom in until labels densify
  for (let i = 0; i < 8; i++) {
    await page.getByRole('button', { name: 'Zoom in' }).click();
    await page.waitForTimeout(80);
  }
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-zoomed.png'), fullPage: true });

  // Search fly-to
  await page.getByTestId('trust-map-search').fill('Ada Lovelace');
  await page.getByTestId('trust-map-search-go').click();
  await page.waitForTimeout(600);
  await expect(page.getByTestId('trust-map-nameplate')).toBeVisible();
  await expect(page.getByTestId('trust-map-nameplate')).toContainText('Ada');
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-search-ada.png'), fullPage: true });

  // Browse labels
  await page.getByRole('button', { name: 'Browse' }).click();
  await page.waitForTimeout(400);
  for (let i = 0; i < 5; i++) {
    await page.getByRole('button', { name: 'Zoom in' }).click();
  }
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-browse.png'), fullPage: true });
});
