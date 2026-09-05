import { test, expect } from '@playwright/test';

test.describe('collapsible top-nav', () => {
  test('phone: wordmark stays, no horizontal scroll, Help is labelled in Menu', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/');

    const wordmark = page.getByTestId('top-nav-wordmark');
    await expect(wordmark).toBeVisible();
    await expect(wordmark).toHaveText(/SVRNTY\.IS YOURS/);

    await expect(page.getByTestId('top-nav-menu-btn')).toBeVisible();
    await expect(page.getByTestId('top-nav-desktop')).toBeHidden();

    const before = await wordmark.boundingBox();
    expect(before).toBeTruthy();

    const overflowX = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth
    );
    expect(overflowX).toBeLessThanOrEqual(1);

    await page.getByTestId('top-nav-menu-btn').click();
    await expect(page.getByTestId('top-nav-menu')).toBeVisible();
    await expect(page.getByTestId('nav-help-menu')).toBeVisible();
    await expect(page.getByTestId('nav-help-menu')).toHaveText(/Help/i);

    const after = await wordmark.boundingBox();
    expect(after?.x).toBe(before?.x);
    expect(after?.y).toBe(before?.y);
    expect(after?.width).toBe(before?.width);

    await page.getByTestId('nav-help-menu').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByRole('dialog').getByText(/the formula/i).first()).toBeVisible();
  });

  test('desktop: full action row, Menu hidden', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/');

    await expect(page.getByTestId('top-nav-wordmark')).toBeVisible();
    await expect(page.getByTestId('top-nav-desktop')).toBeVisible();
    await expect(page.getByTestId('top-nav-menu-btn')).toBeHidden();
    await expect(page.getByRole('button', { name: 'Help' })).toBeVisible();
  });

  test('phone after identity: Recovery is a labelled Menu item and opens the sheet', async ({
    page,
  }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/');

    await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
    await page.getByPlaceholder('Your name').fill('Nav E2E');
    await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
    await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
    await page.getByRole('button', { name: /^start$/i }).click();
    await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
    await page.getByRole('button', { name: /i have it/i }).click();
    await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
      timeout: 20_000,
    });

    await expect(page.getByTestId('nav-recovery')).toBeHidden();
    await page.getByTestId('top-nav-menu-btn').click();
    await expect(page.getByTestId('nav-recovery-menu')).toBeVisible();
    await expect(page.getByTestId('nav-recovery-menu')).toHaveText(/Recovery/i);
    await expect(page.getByTestId('nav-help-menu')).toBeVisible();
    await expect(page.getByTestId('nav-grow-menu')).toBeVisible();
    await expect(page.getByTestId('nav-join-menu')).toHaveCount(0);

    await page.getByTestId('nav-recovery-menu').click();
    await expect(page.getByRole('dialog', { name: 'Recovery' })).toBeVisible();
  });
});
