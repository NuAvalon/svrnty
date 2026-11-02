import { test, expect, type Page } from '@playwright/test';
import { seedSampleGalaxy } from './helpers/seed-sample-galaxy';

/** Sample-circle Ada — the fixture's old "mutual" circle. Since #593 (affirm wire removed) NOTHING in-app can make an edge mutual; only PSI (#588) will. She reads one-way, like Alan. */
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

// Pins the HONEST post-#593 state (Hypatia claims ruling, lane:svrnty #912): the sample galaxy has NO white/lit node and nothing says
// "Mutual trust", "Trust pending" or "Awaiting mutual". Every trusted sample contact reads exactly "Trusted" (own-trust, one-way).
// This file was trust-visual-pending-mutual.spec.ts; the old name described a wait that no longer exists.
// When PSI (#588) re-grounds mutual, ADD a mutual fixture here; do not loosen these negatives.
test('Galaxy: one-way trust is the only state; nothing is white-lit or mutual (#593)', async ({
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

  // Ada is one-way now, exactly like Alan: trust-sent, not white, not mutual.
  await expect(ada).toHaveAttribute('data-bond-state', 'trust-sent');
  await expect(ada).not.toHaveAttribute('data-light', 'white');
  await expect(ada).toHaveAttribute('data-mutual', 'false');
  // No node anywhere in the sample galaxy is lit or mutual.
  await expect(page.locator('[data-testid="trust-node"][data-light="white"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="trust-node"][data-mutual="true"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="trust-node-light"]')).toHaveCount(0);

  await expect(alan).toHaveAttribute('data-bond-state', 'trust-sent');
  await expect(alan).not.toHaveAttribute('data-light', 'white');
  await expect(alan).toHaveAttribute('data-mutual', 'false');
  await expect(alan).toHaveAttribute('data-shape', 'hex');
  await expect(ada).toHaveAttribute('data-shape', 'hex');
  await expect(alan).toHaveAttribute('data-spoke-style', 'single');
  const adaFill = await ada.getAttribute('fill');
  const alanFill = await alan.getAttribute('fill');
  expect(alanFill, 'both one-way contacts share the same hex fill').toBe(adaFill);
  expect(alanFill).toBeTruthy();
  expect(alanFill).not.toBe('transparent');
  await expect(page.locator(`g[data-graph-node="${ALAN}"] [data-testid="trust-node-light"]`)).toHaveCount(0);
  await expect(page.locator(`g[data-graph-node="${ADA}"] [data-testid="trust-node-light"]`)).toHaveCount(0);
  await expect(page.locator('[data-testid="trust-node-awaiting"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="trust-node-inbound-half"]')).toHaveCount(0);

  // Intro handshake is a separate axis from trust-sent (Frank is not one-way trust).
  await expect(frank).not.toHaveAttribute('data-bond-state', 'trust-sent');
  await expect(frank).not.toHaveAttribute('data-light', 'white');
  await expect(frank).toHaveAttribute('data-bond-state', 'known');

  await expect(page.getByTestId('trust-lifecycle-legend')).toContainText(/Known/i);
  await expect(page.getByTestId('trust-lifecycle-legend')).toContainText(/Trusted/i);
  await expect(page.getByTestId('trust-legend-glyph-known')).toBeVisible();
  await expect(page.getByTestId('trust-legend-glyph-trust-sent')).toBeVisible();
  await expect(page.getByTestId('trust-legend-glyph-known').locator('polygon')).toHaveCount(1);
  await expect(page.getByTestId('trust-legend-glyph-trust-sent').locator('circle')).toHaveCount(0);
  // The honest negatives: no CONTACT is described as mutual, pending trust, or awaiting one (node titles carry "<name> — <label>").
  // The legend is pinned separately, below.
  await expect(page.getByTestId('trust-lifecycle-legend')).not.toContainText(/outer|half|awaiting|unverified|Trust pending/i);
  const titles = await page.locator('[data-testid="trust-node"] title').allTextContents();
  expect(titles.length, 'node titles were read').toBeGreaterThan(0);
  for (const t of titles) expect(t, `node title: ${t}`).not.toMatch(/Mutual trust|Trust pending|Awaiting mutual/i);
  await expect(page.getByTestId('trust-map-consent-legend')).toContainText(
    /Every visible line consented — none inferred/,
  );

  // Galaxy nodes animate (tm-ignite entrance + infinite tm-pulse), so Playwright's click
  // actionability wait for a "stable" (non-moving) element flakes under CI load — a latent
  // timing flake, not a render regression (the structural attrs + legend above already proved
  // the visual state with animations live). Freeze animations for the interaction only, so the
  // node clicks land on a static target deterministically. No render change.
  await page.addStyleTag({
    content: '*, *::before, *::after { animation: none !important; transition: none !important; }',
  });

  // Dispatch the click directly rather than a geometric click: the galaxy node keeps moving
  // (residual JS/layout motion the CSS freeze above can't fully stop), so a position-based
  // click flakes on a stale bounding box. dispatchEvent fires the node's handler deterministically
  // — which is exactly the intent under test (selecting a node reveals its honest bond-label); a
  // real user tracks the moving node fine. Not a render change.
  await alan.dispatchEvent('click');
  await expect(page.getByTestId('trust-node-bond-label')).toHaveText('Trusted');
  await ada.dispatchEvent('click');
  await expect(page.getByTestId('trust-node-bond-label')).toHaveText('Trusted');
  // #253 ember no-op: inbound distress PAINT is gated off (VivreBurn returns null) while the
  // emit-path is unwired. KEEP data-distress (raw distress value — benign data hook, proves the
  // fixture puts ada in a REAL distress state); ASSERT the paint is absent. This pair IS the
  // survivor-safety guard (distress-present contact ⟹ zero paint in DOM) — a premature re-enable
  // regression must fail it (test-side partner to chaos #144; Flint-signed invariant).
  await expect(ada).toHaveAttribute('data-distress', 'true');
  await expect(page.getByTestId('trust-node-detail').getByTestId('vivre-burn')).toHaveCount(0);
});

test('Address book chips: Ada and Alan both read exactly "Trusted" (#593); no chip says mutual', async ({ page }) => {
  test.setTimeout(90_000);
  await genesis(page, 'Book Visual');
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await seedSampleGalaxy(page);
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();

  const adaRow = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Ada Lovelace' });
  const alanRow = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Alan Turing' });
  await expect(adaRow.getByTestId('master-row-chip')).toHaveText('Trusted');
  await expect(adaRow.getByTestId('master-row-chip')).toHaveAttribute('data-bond-state', 'trust-sent');
  // No chip on the whole address book says mutual / pending / awaiting.
  await expect(page.getByTestId('master-row-chip').filter({ hasText: /Mutual trust|Trust pending|Awaiting mutual/i })).toHaveCount(0);
  await expect(page.locator('[data-testid="master-row-chip"][data-bond-state="mutual"]')).toHaveCount(0);
  // #253 ember no-op: keep data-distress (raw value, benign) — proves ada is a real distress
  // contact — and assert the distress PAINT is absent (vivre-burn/caution return null). The
  // distress-present ⟹ zero-paint pair is the survivor-safety guard; don't delete it.
  await expect(adaRow).toHaveAttribute('data-distress', '1');
  await expect(adaRow.getByTestId('vivre-burn')).toHaveCount(0);
  await adaRow.click();
  await expect(page.getByTestId('contact-action-card').getByTestId('vivre-burn')).toHaveCount(0);
  await expect(page.getByTestId('vivre-caution')).toHaveCount(0);
  await expect(alanRow.getByTestId('master-row-chip')).toHaveText('Trusted');
  await expect(alanRow.getByTestId('master-row-chip')).toHaveAttribute('data-bond-state', 'trust-sent');
});

// The Galaxy legend lists only the keys a user can actually reach. Since #593 nothing in-app can produce a mutual edge (PSI #588 re-grounds it),
// so a "Mutual trust" key with a white-core glyph would say the state exists (Hypatia #924: the same dormant-overclaim shape as the removed
// "Trust is mutual" arm). When #588 lands, add the key back TOGETHER with a fixture that can reach it, and flip this test.
test('Galaxy legend does not list a "Mutual trust" key while no in-app path can produce one (#593)', async ({ page }) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await genesis(page, 'Legend Honest');
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await seedSampleGalaxy(page);
  await expect(page.getByTestId('trust-lifecycle-legend')).not.toContainText(/Mutual trust/i);
  await expect(page.getByTestId('trust-legend-glyph-mutual')).toHaveCount(0);
});
