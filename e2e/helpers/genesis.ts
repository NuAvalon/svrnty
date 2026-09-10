import { expect, type Page } from '@playwright/test';

/** Empty-device genesis: Grow mints the card. Home has no Start door. */
export async function openGrow(page: Page) {
  await expect(page.getByTestId('top-nav-wordmark')).toBeVisible();
  const grow = page.getByTestId('nav-grow');
  if (await grow.isVisible()) {
    await grow.click();
  } else {
    await page.getByTestId('top-nav-menu-btn').click();
    await page.getByTestId('nav-grow-menu').click();
  }
}

export async function genesis(page: Page, name: string) {
  await page.goto('/');
  await openGrow(page);
  await expect(page.getByPlaceholder('your@email.com')).toHaveCount(0);
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByTestId('grow-forge-submit').click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 20_000,
  });
}
