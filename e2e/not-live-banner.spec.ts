import { test, expect } from '@playwright/test';

const WORDS = "svrnty isn't live yet. It's in development, so please don't rely on it. If you're using it, please email nuavalon@proton.me so we know.";

test('the home page says it is not live, and how to reach us', async ({ page }) => {
  await page.goto('/');
  const banner = page.getByTestId('not-live-banner');
  await expect(banner).toBeVisible();
  await expect(banner).toHaveText(WORDS);
  await expect(banner.getByRole('link', { name: 'nuavalon@proton.me' })).toHaveAttribute('href', 'mailto:nuavalon@proton.me');
});

test('the banner is in the first HTML, before any script runs', async ({ request }) => {
  const html = await (await request.get('/')).text();
  expect(html).toContain('data-testid="not-live-banner"');
  expect(html).toContain('live yet');
  expect(html).toContain('mailto:nuavalon@proton.me');
});
