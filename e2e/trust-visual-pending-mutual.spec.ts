import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

/** Sample-circle Ada — mutual. */
const ADA = 'a11a10e1ace00000000000000000000000000001';
/** Sample-circle Alan — trusted, not reciprocal (the Peter miss). */
const ALAN = 'a1a2011216000000000000000000000000000002';
/** Sample-circle Frank — pending intro, not trust-sent. */
const FRANK = 'f1a2000000000000000000000000000000000007';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('trust-visual@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

// Labels assert PRE-WIRE gated copy (isMutualTrustWireLive=false → Trusted).
// Structural attrs (bond-state/light/shape/hex fill) are ungated. Flip labels with the wire.
test('Galaxy: one-way trust is not white; Mutual trust is the only white light', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await genesis(page, 'Trust Visual');
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await seedSampleGalaxy(page);

  const ada = page.locator(`[data-testid="trust-node"][data-fingerprint="${ADA}"]`);
  const alan = page.locator(`[data-testid="trust-node"][data-fingerprint="${ALAN}"]`);
  const frank = page.locator(`[data-testid="trust-node"][data-fingerprint="${FRANK}"]`);

  await expect(ada).toHaveAttribute('data-bond-state', 'mutual');
  await expect(ada).toHaveAttribute('data-light', 'white');
  await expect(ada).toHaveAttribute('data-mutual', 'true');

  await expect(alan).toHaveAttribute('data-bond-state', 'trust-sent');
  await expect(alan).not.toHaveAttribute('data-light', 'white');
  await expect(alan).toHaveAttribute('data-mutual', 'false');
  await expect(alan).toHaveAttribute('data-shape', 'hex');
  await expect(ada).toHaveAttribute('data-shape', 'hex');
  await expect(alan).toHaveAttribute('data-spoke-style', 'single');
  const adaFill = await ada.getAttribute('fill');
  const alanFill = await alan.getAttribute('fill');
  expect(alanFill, 'one-way hex fill matches mutual').toBe(adaFill);
  expect(alanFill).toBeTruthy();
  expect(alanFill).not.toBe('transparent');
  await expect(page.locator(`g[data-graph-node="${ALAN}"] [data-testid="trust-node-light"]`)).toHaveCount(0);
  await expect(page.locator(`g[data-graph-node="${ADA}"] [data-testid="trust-node-light"]`)).toHaveCount(1);
  await expect(page.locator('[data-testid="trust-node-awaiting"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="trust-node-inbound-half"]')).toHaveCount(0);

  // Intro handshake is a separate axis from trust-sent (Frank is not one-way trust).
  await expect(frank).not.toHaveAttribute('data-bond-state', 'trust-sent');
  await expect(frank).not.toHaveAttribute('data-light', 'white');
  await expect(frank).toHaveAttribute('data-bond-state', 'known');

  await expect(page.getByTestId('trust-lifecycle-legend')).toContainText(/Known/i);
  await expect(page.getByTestId('trust-lifecycle-legend')).toContainText(/Trusted/i);
  await expect(page.getByTestId('trust-lifecycle-legend')).toContainText(/Mutual trust/i);
  await expect(page.getByTestId('trust-lifecycle-legend')).not.toContainText(
    /outer|half|awaiting|unverified|Trust pending/i,
  );
  await expect(page.getByTestId('trust-map-consent-legend')).toContainText(
    /Every visible line consented — none inferred/,
  );

  await alan.click({ force: true });
  await expect(page.getByTestId('trust-node-bond-label')).toHaveText('Trusted');
  await ada.click({ force: true });
  await expect(page.getByTestId('trust-node-bond-label')).toHaveText('Mutual trust');
});

test('Address book chips: Ada Mutual trust, Alan Trusted (pre-wire)', async ({ page }) => {
  test.setTimeout(90_000);
  await genesis(page, 'Book Visual');
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await seedSampleGalaxy(page);
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();

  const adaRow = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Ada Lovelace' });
  const alanRow = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Alan Turing' });
  await expect(adaRow.getByTestId('master-row-chip')).toHaveText('Mutual trust');
  await expect(adaRow.getByTestId('master-row-chip')).toHaveAttribute('data-bond-state', 'mutual');
  await expect(alanRow.getByTestId('master-row-chip')).toHaveText('Trusted');
  await expect(alanRow.getByTestId('master-row-chip')).toHaveAttribute('data-bond-state', 'trust-sent');
});
