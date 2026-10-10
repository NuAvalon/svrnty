import { expect, type Page } from '@playwright/test';

/**
 * Product chrome no longer ships "Load sample circle". Playwright sets
 * navigator.webdriver, which installs window.__svrntySeedSampleCircle
 * (addContact path — enc-b). Call after genesis while Galaxy is visible.
 */
export const SAMPLE_TESLA_FP = '7e51a00000000000000000000000000000000008';

export async function seedSampleGalaxy(page: Page): Promise<number> {
  await expect
    .poll(async () => page.evaluate(() => typeof (window as unknown as { __svrntySeedSampleCircle?: unknown }).__svrntySeedSampleCircle), {
      timeout: 20_000,
    })
    .toBe('function');
  const n = await page.evaluate(async () => {
    const fn = (window as unknown as { __svrntySeedSampleCircle?: () => Promise<number> })
      .__svrntySeedSampleCircle;
    return fn ? fn() : 0;
  });
  expect(n, 'webdriver sample seed wrote contacts').toBeGreaterThan(0);
  await expect(page.getByTestId('trust-node').first()).toBeVisible({ timeout: 20_000 });
  return n;
}
