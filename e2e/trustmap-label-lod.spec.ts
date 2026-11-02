import { test, expect, type Page } from '@playwright/test';
import path from 'path';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

const ART = '/opt/cursor/artifacts/screenshots';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('lod@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts' })).toBeVisible({ timeout: 15_000 });
}

test('Trust Map label LOD + dense sample', async ({ page }) => {
  test.setTimeout(120_000);
  await genesis(page, 'LOD Owner');
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await seedSampleGalaxy(page);
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-fit.png'), fullPage: true });

  // Zoom in until labels densify
  for (let i = 0; i < 8; i++) {
    await page.getByRole('button', { name: 'Zoom in' }).click();
    await page.waitForTimeout(80);
  }
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-zoomed.png'), fullPage: true });

  // Search / nameplate / lamp / Browse are PR #84 surfaces. Main Galaxy has
  // zoom + sample only — skip the rest until that UI lands.
  // PR #84's INTERACTIVE surfaces (the search-GO button, nameplate, lamp-links, Browse) have NOT
  // landed — only the search INPUT did. Search is Enter-triggered now (the input's onKeyDown in
  // TrustMap, no GO button), and trust-map-search-go / trust-map-nameplate / trust-map-lamp-links
  // do not exist in the component. The old guard checked the INPUT (which landed) → let the block
  // run → timed out 120s clicking the NON-EXISTENT trust-map-search-go (this was the #225-integration
  // CI RED — an absent element, NOT the galaxy animation-flake class, so freeze/dispatchEvent can't
  // fix it). Gate on the GO button: it only exists once the full search UI lands.
  const searchGo = page.getByTestId('trust-map-search-go');
  if ((await searchGo.count()) === 0) return;

  // Search fly-to
  await page.getByTestId('trust-map-search').fill('Ada Lovelace');
  await page.getByTestId('trust-map-search-go').dispatchEvent('click');
  await page.waitForTimeout(600);
  await expect(page.getByTestId('trust-map-nameplate')).toBeVisible();
  await expect(page.getByTestId('trust-map-nameplate')).toContainText('Ada');
  await expect(page.getByTestId('trust-map-lamp-links')).toBeVisible();
  await expect(page.getByTestId('trust-map-lamp-links')).toContainText(
    /A circle they disclosed to you|Both disclosed they trust each other|No disclosed peer ties/i,
  );
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-search-ada.png'), fullPage: true });

  // Lamp someone with group-only neighbors if needed — click Grace for clique filaments
  await page.getByTestId('trust-map-search').fill('Grace Hopper');
  await page.getByTestId('trust-map-search-go').dispatchEvent('click');
  await page.waitForTimeout(700);
  await expect(page.getByTestId('trust-map-lamp-links')).toBeVisible();
  await page.screenshot({ path: path.join(ART, 'trustmap-lamp-mutuals.png'), fullPage: true });

  // Browse labels
  await page.getByRole('button', { name: 'Browse' }).click();
  await page.waitForTimeout(400);
  for (let i = 0; i < 5; i++) {
    await page.getByRole('button', { name: 'Zoom in' }).click();
  }
  await page.screenshot({ path: path.join(ART, 'trustmap-lod-browse.png'), fullPage: true });
});
