import { test, expect, type Page } from '@playwright/test';

// One-step Connect-UX glass (CURSOR_QUEUE #3). Persist is a stub — Add to Known stays
// disabled. Live Scan/paste still mounts JoinerCeremony.

const FRAG = 'e2econnectfrag';
const CODE = 'e2econnect';
const LINK = `https://svrnty.is/c/${CODE}#${FRAG}`;

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('connect-ux@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

test.describe('Connect-UX one-step glass', () => {
  test('Grow paste field: Gate chrome, Add to Known disabled, fragment never rendered', async ({
    page,
  }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Connect Glass');

    await page.getByTestId('nav-grow').click();
    const dialog = page.getByTestId('grow-surface');
    await expect(dialog).toBeVisible();

    const connect = dialog.getByTestId('connect-one-step');
    await expect(connect).toBeVisible();
    await expect(connect.getByLabel(/paste a connect link/i)).toBeVisible();

    await connect.getByTestId('connect-paste-input').fill(LINK);
    await connect.getByTestId('connect-open').click();

    await expect(dialog.getByTestId('connect-arrival')).toBeVisible();
    await expect(dialog.getByTestId('connect-not-wired')).toBeVisible();
    await expect(dialog.getByTestId('connect-add-known')).toBeDisabled();
    await expect(dialog.getByTestId('connect-entity-type')).toHaveText(/not yet attested/i);

    await expect(page.locator('body')).not.toContainText(FRAG);
    await expect(page.locator('body')).not.toContainText('javascript:');

    // Live Scan/paste ceremony path is still there (do not break grow-2tab).
    await dialog.getByRole('tab', { name: 'Scan / paste' }).click();
    await expect(dialog.getByLabel(/paste your invite link/i)).toBeVisible();
  });

  test('/c/{code} still mounts the live ceremony while add-logic is unwired', async ({ page }) => {
    test.setTimeout(60_000);
    await genesis(page, 'Connect Route');
    await page.goto(`/c/${CODE}#${FRAG}`);
    await expect(page.getByText(/opening the secure channel|missing decryption key|expired/i)).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.locator('body')).not.toContainText(FRAG);
    await expect(page.getByTestId('connect-one-step')).toHaveCount(0);
  });
});
