import { test, expect } from '@playwright/test';
import { genesis } from './helpers/genesis';
import { readFile } from 'node:fs/promises';

// Drives the REAL create-identity flow to the unlocked app. This is the foundation every demo-arc
// spec needs — contact import and the trust ceremony both require an unlocked identity. Real
// in-browser keygen runs here (ED25519 + ML-DSA-87 signing, Curve25519 + ML-KEM-1024 encryption),
// so the unlock assertion gets a generous timeout. Each test gets a fresh browser context, so the
// IndexedDB identity store starts empty.
test('create an identity → land in the unlocked app', async ({ page }) => {
  test.setTimeout(60_000);
  await genesis(page, 'Alice E2E');

  await page.getByRole('tab', { name: 'Identity' }).click();
  await expect(page.getByTestId('export-own-vcf')).toBeVisible();

  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('export-own-vcf').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/\.vcf$/i);
  const dest = test.info().outputPath('own-card.vcf');
  await download.saveAs(dest);
  const vcf = await readFile(dest, 'utf8');
  expect(vcf).toContain('BEGIN:VCARD');
  expect(vcf).toContain('FN:Alice E2E');
  expect(vcf).not.toContain('CATEGORIES');
  expect(vcf).not.toMatch(/blocked/i);
});
