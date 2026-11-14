import { test, expect } from '@playwright/test';

// CI runs with the setting unset, which must mean off. E2E_EXPECT_BANNER=on is for a server started with it on.
const expectOn = process.env.E2E_EXPECT_BANNER === 'on';
const WORDS = "svrnty isn't live yet. It's in development, so please don't rely on it. If you're using it, please email nuavalon@proton.me so we know.";

test.describe('setting on', () => {
  test.skip(!expectOn, 'needs a server started with SVRNTY_NOT_LIVE_BANNER=on');

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
  });

  test('only the home page shows it, and a forged header cannot change that', async ({ request }) => {
    const html = await (await request.get('/u/nobody', { headers: { 'x-svrnty-path': '/' } })).text();
    expect(html).not.toContain('data-testid="not-live-banner"');
  });
});

test.describe('setting off', () => {
  test.skip(expectOn, 'the server has the setting on');

  test('no banner in the first HTML or on the page', async ({ page, request }) => {
    expect(await (await request.get('/')).text()).not.toContain('data-testid="not-live-banner"');
    await page.goto('/');
    await expect(page.getByTestId('not-live-banner')).toHaveCount(0);
  });
});
