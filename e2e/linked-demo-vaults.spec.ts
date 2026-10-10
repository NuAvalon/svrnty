import { test, expect, type Page } from '@playwright/test';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('linked-demo@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

test('Load sample mints linked vaults; Chat and Actions match', async ({ page }) => {
  test.setTimeout(210_000);
  await page.setViewportSize({ width: 390, height: 844 });
  await genesis(page, 'Demo Owner');

  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  const load = page.getByTestId('trust-map-load-sample');
  await expect(load).toBeVisible();
  await load.click();
  await expect(load).toHaveText('Loading…');
  await expect(load).toBeHidden({ timeout: 150_000 });

  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(page.getByTestId('contact-row').filter({ hasText: 'Hypatia' })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByTestId('contact-row').filter({ hasText: 'River Vale' })).toBeVisible();
  await expect(page.getByTestId('contact-row').filter({ hasText: 'Sage Quinn' })).toBeVisible();

  await page.getByTestId('contact-row').filter({ hasText: 'Hypatia' }).click();
  const classical = page.getByTestId('contact-action-card');
  await expect(classical).toBeVisible();
  await expect(classical.getByTestId('classical-no-key')).toBeVisible();
  await expect(classical.getByTestId('classical-no-fingerprint')).toBeVisible();
  await expect(classical.getByTestId('galaxy-open-note')).toHaveCount(0);
  await expect(classical.getByTestId('card-actions-toggle')).toBeVisible();
  await page.screenshot({
    path: '/opt/cursor/artifacts/screenshots/classical-card-no-key.png',
    fullPage: true,
  });

  await page.getByTestId('contact-row').filter({ hasText: 'River Vale' }).click();
  const living = page.getByTestId('contact-action-card');
  await expect(living).toBeVisible();
  await expect(living.getByTestId('classical-no-key')).toHaveCount(0);
  await expect(living.getByTestId('living-fingerprint')).toBeVisible();
  const chat = living.getByTestId('galaxy-open-note');
  const actions = living.getByTestId('card-actions-toggle');
  await expect(chat).toBeVisible();
  await expect(actions).toBeVisible();
  const chatBox = await chat.boundingBox();
  const actBox = await actions.boundingBox();
  expect(chatBox, 'Chat button box').toBeTruthy();
  expect(actBox, 'Actions button box').toBeTruthy();
  expect(Math.abs((chatBox?.height || 0) - (actBox?.height || 0))).toBeLessThan(2);
  expect(Math.abs((chatBox?.width || 0) - (actBox?.width || 0))).toBeLessThan(2);
  await page.screenshot({
    path: '/opt/cursor/artifacts/screenshots/living-card-equal-verbs.png',
    fullPage: true,
  });

  await page.getByTestId('top-nav-menu-btn').click();
  await page.getByTestId('nav-lock-menu').click();
  await expect(page.getByTestId('switch-identity')).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('switch-identity-option').filter({ hasText: 'River Vale' })).toBeVisible();
  await expect(page.getByTestId('switch-identity-option').filter({ hasText: 'Sage Quinn' })).toBeVisible();
  await expect(
    page.getByTestId('switch-identity-option').filter({ hasText: 'River Vale' }).getByTestId('switch-identity-seal'),
  ).toBeVisible();
  await page.screenshot({
    path: '/opt/cursor/artifacts/screenshots/switch-identity-linked-vaults.png',
    fullPage: true,
  });
});
