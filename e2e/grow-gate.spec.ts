import { test, expect, type Page } from '@playwright/test';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('grow-gate@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

test.describe('Grow Gate chrome', () => {
  test('remote default keeps viral cap; in person hides it and shows Gate', async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Gate Chrome');

    await page.getByTestId('nav-grow').click();
    const dialog = page.getByTestId('grow-surface');
    await expect(dialog).toBeVisible();

    await expect(dialog.getByTestId('grow-gate-list')).toBeVisible();
    await expect(dialog.getByText(/no one waiting/i)).toBeVisible();

    await expect(dialog.getByTestId('grow-channel-remote')).toHaveAttribute('aria-pressed', 'true');
    await expect(
      dialog.getByLabel(/number of people who can join with this link/i),
    ).toBeVisible();

    await dialog.getByTestId('grow-channel-in-person').click();
    await expect(dialog.getByTestId('grow-channel-in-person')).toHaveAttribute('aria-pressed', 'true');
    await expect(
      dialog.getByLabel(/number of people who can join with this link/i),
    ).toHaveCount(0);
    await expect(dialog.getByText(/single-use/i).first()).toBeVisible();
    await expect(dialog.getByText(/mint it when they are in front of you/i)).toBeVisible();
  });

  test('Galaxy membrane opens a searchable Gate overlay', async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Gate Galaxy');

    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    const gate = page.getByTestId('galaxy-gate');
    await expect(gate).toBeVisible();
    await expect(gate).toHaveAttribute('data-count', '0');
    await expect(page.getByTestId('trust-map')).toBeVisible();

    await gate.click();
    await expect(page.getByTestId('galaxy-gate-overlay')).toBeVisible();
    await expect(page.getByTestId('galaxy-gate-search')).toBeVisible();
    await expect(page.getByTestId('galaxy-gate-overlay-close')).toBeVisible();
    await page.getByTestId('galaxy-gate-overlay-close').click();
    await expect(page.getByTestId('galaxy-gate-overlay')).toHaveCount(0);
  });

  test('sample Known stars ignite on first appearance', async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Gate Ignite');

    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    await page.getByTestId('trust-map-load-sample').click();
    await expect(page.locator('[data-testid="trust-node"][data-ignite="true"]').first()).toBeVisible({
      timeout: 20_000,
    });
  });
});
