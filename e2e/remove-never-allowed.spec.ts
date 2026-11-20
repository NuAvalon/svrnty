import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { seedAliceWithBob } from './fixtures/deposit-note';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * Removing a contact must not tell the satellite about someone it never heard of, in the REAL app (the real shell, contact book, card menu and confirm).
 * The satellite mirror holds a row for a contact only while open visibility is on (and they are not blocked or private). A contact who never had a row (every freshly imported one) has nothing to revoke,
 * and a DELETE for them would only tell the satellite's operator that fingerprint.
 *  - NEG: removing a contact who never had a row sends no request to /api/satellite/allowed.
 *  - CONTROL (so "none" means none): removing a contact who DID have a row (trusted, open visibility on) sends exactly one DELETE for that pair. The page's satellite traffic is recorded at the route, so a
 *    request the app makes is seen whether or not anything answers it.
 * The reconcile runs only on a dev build (the domain starts with "dev."). The standing CI server is started without that domain, so there the gate is dark: the control then sees no traffic and BOTH tests
 * skip, saying why (the unit tests and the source guard are what CI runs for this rule). To run it for real: start the server with NEXT_PUBLIC_SVRNTY_DOMAIN=dev.svrnty.is and set E2E_EXPECT_PSI_GATE=1, which turns a dark
 * gate into a FAILURE instead of a skip, so a runner that means to test this cannot pass without testing it.
 */
const PASS = 'e2e-passphrase-1234';
const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PASS);
  await page.getByPlaceholder('Confirm passphrase').fill(PASS);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

/** Every request the page makes to the satellite's allowed-senders list, recorded at the route and answered 200 (nothing real is reached). */
async function recordAllowed(page: Page) {
  const seen: Array<{ method: string; url: string }> = [];
  await page.route('**/api/satellite/allowed/**', async (route) => {
    seen.push({ method: route.request().method(), url: route.request().url() });
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  return seen;
}

async function setup(page: Page, openVisible: boolean) {
  await genesis(page, 'Alice Removes');
  const seeded = await seedAliceWithBob(page);
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  await page.evaluate(([o, p]) => window.__fz.initApp(o, p), [seeded.aliceFp, PASS]);
  const bobId = `e2e-bob-${seeded.bob.fingerprint.slice(0, 12)}`;
  if (openVisible) await page.evaluate(([id]) => window.__fz.setOpenVisible(id as string, true), [bobId]);
  return { aliceFp: seeded.aliceFp.toLowerCase(), bobFp: seeded.bob.fingerprint.toLowerCase(), bobId };
}

/** Contacts tab -> Bob's row -> his card's menu -> Remove -> Remove again in the confirm; then Bob is gone from the book. */
async function removeBob(page: Page) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  const row = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' }).first();
  await expect(row).toBeVisible({ timeout: 25_000 });
  await row.click();
  const card = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  await expect(card).toBeVisible();
  const toggle = card.getByTestId('card-actions-toggle');
  await toggle.scrollIntoViewIfNeeded();
  await toggle.click({ timeout: 10_000 });
  await card.getByTestId('card-actions-toggle-menu').getByRole('menuitem', { name: 'Remove', exact: true }).click();
  const confirm = page.getByTestId('trust-action-confirm');
  await expect(confirm).toBeVisible();
  await confirm.getByTestId('trust-action-confirm-btn').click();
  await expect(confirm).toHaveCount(0);
  await expect(page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' }), 'Bob is really gone from the book').toHaveCount(0);
}

test.describe('Remove and the satellite allowed-senders list', () => {
  test.describe.configure({ mode: 'serial' });   // the negative case relies on what the control found out about the gate
  test.setTimeout(180_000);
  let gateOn: boolean | null = null;

  test('CONTROL: removing a contact who HAD a row (trusted, open visibility on) sends exactly one DELETE for that pair (this also proves the gate is on in this build)', async ({ page }) => {
    const seen = await recordAllowed(page);
    const s = await setup(page, true);
    await removeBob(page);
    await page.waitForTimeout(6_000);   // the reconcile is fire-and-forget
    gateOn = seen.length > 0;
    if (!gateOn) {
      expect(process.env.E2E_EXPECT_PSI_GATE, 'the PSI gate is dark in this build (is NEXT_PUBLIC_SVRNTY_DOMAIN a dev. domain?) but this run was told to expect it').toBeFalsy();
      test.skip(true, 'the PSI gate is dark in this build, so Remove sends nothing either way: nothing to tell apart (the unit tests and the source guard cover the rule here)');
    }
    expect(seen.map((r) => r.method), 'exactly one request, and it is a DELETE').toEqual(['DELETE']);
    expect(seen[0].url.toLowerCase().endsWith(`/api/satellite/allowed/${s.aliceFp}/${s.bobFp}`), seen[0].url).toBe(true);
  });

  test('NEG: removing a contact who NEVER had a row (a fresh, never-exchanged contact) sends the satellite no request at all', async ({ page }) => {
    test.skip(gateOn === false, 'the control found the PSI gate dark in this build: "no request" would prove nothing');
    expect(gateOn, 'the control ran first and found out whether the gate is on').not.toBeNull();
    const seen = await recordAllowed(page);
    await setup(page, false);
    await removeBob(page);
    await page.waitForTimeout(5_000);   // longer than the control needed to be seen
    expect(seen, `no request to the allowed-senders list (saw ${JSON.stringify(seen)})`).toEqual([]);
  });
});
