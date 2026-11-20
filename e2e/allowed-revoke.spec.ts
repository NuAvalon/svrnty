import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { seedAliceWithBob } from './fixtures/deposit-note';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * The satellite's allowed-senders list is owed a DELETE for exactly the people it still LISTS whose consent no longer allows a row, in the REAL app (the real shell and book, the real hook and
 * the real tick step). The test's relay KEEPS A LIST: GET lists it, POST adds a sender, a 2xx DELETE removes one; every request is recorded at the route.
 *  - CONTROL: a person the relay lists (added through the real hook) gets exactly one DELETE when removed, and the relay then lists nothing.
 *  - NEG: a person the relay does NOT list (the fresh-import default) is removed with NO DELETE: the app asks for the owner's own list, and no request names the person.
 *  - TICK: rows the relay still lists with NO local record (a removed contact whose DELETE never went out) and for a contact blocked locally are both revoked by the tick; a GET that FAILS
 *    revokes nothing and loses nothing; a DELETE the relay refuses stays listed and is sent again once its retry window has passed.
 * The reconcile runs only on a dev build (the domain starts with "dev."): see how the gate is turned on and what E2E_EXPECT_PSI_GATE does in the run script's header (run941.sh).
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

type Seen = { method: string; url: string };
interface Relay { list: Set<string>; seen: Seen[]; getStatus: number; deleteStatus: number; console: string[] }

/** A relay that keeps a list, answered at the route (nothing real is reached). */
async function mockRelay(page: Page, init: { list?: string[] } = {}): Promise<Relay> {
  const relay: Relay = { list: new Set(init.list ?? []), seen: [], getStatus: 200, deleteStatus: 200, console: [] };
  page.on('console', (m) => { const t = m.text(); if (/\[psi\]|allowed/i.test(t)) relay.console.push(t.slice(0, 300)); });   // so a fail-soft skip inside the app is visible, not silent
  await page.route('**/api/satellite/allowed/**', async (route) => {
    const req = route.request(); const method = req.method();
    relay.seen.push({ method, url: req.url() });
    if (method === 'GET') {
      if (relay.getStatus !== 200) return route.fulfill({ status: relay.getStatus, contentType: 'application/json', body: '{}' });
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ owner_fingerprint: 'x', allowed: [...relay.list], count: relay.list.size }) });
    }
    if (method === 'POST') { relay.list.add((req.postDataJSON() as { sender_fingerprint: string }).sender_fingerprint.toLowerCase()); return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }); }
    if (relay.deleteStatus === 200) relay.list.delete(req.url().split('/').pop()!.toLowerCase());
    return route.fulfill({ status: relay.deleteStatus, contentType: 'application/json', body: '{}' });
  });
  return relay;
}
const count = (r: Relay, m: string) => r.seen.filter((s) => s.method === m).length;
const deletes = (r: Relay) => r.seen.filter((s) => s.method === 'DELETE').map((s) => s.url.toLowerCase().split('/').pop());

async function setup(page: Page) {
  await genesis(page, 'Alice Revokes');
  const seeded = await seedAliceWithBob(page);
  await page.addScriptTag({ content: bundle('e2e/helpers/allowed-revoke-harness.ts') });
  await page.evaluate(([o, p]) => window.__fz.initApp(o, p), [seeded.aliceFp, PASS]);
  return { aliceFp: seeded.aliceFp.toLowerCase(), bobFp: seeded.bob.fingerprint.toLowerCase(), bobId: `e2e-bob-${seeded.bob.fingerprint.slice(0, 12)}` };
}

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

test.describe('The satellite allowed list: what it still lists is what is owed', () => {
  test.describe.configure({ mode: 'serial' });
  test.setTimeout(180_000);
  let gateOn: boolean | null = null;

  test('CONTROL: a person the relay LISTS (added through the real hook) gets exactly one DELETE when removed, and the relay then lists nothing (and the Remove path of the app itself proves its gate is on in this build)', async ({ page }) => {
    const relay = await mockRelay(page);
    const s = await setup(page);
    await page.evaluate(([id]) => window.__fz.setOpenVisible(id as string, true), [s.bobId]);
    const added = await page.evaluate(([o, p]) => window.__ar.add(o, p), [s.aliceFp, s.bobFp]);   // direct call, gate forced open (see the harness)
    expect(added, 'the real hook answered an ADD').toEqual({ action: 'add', ok: true });
    expect([...relay.list], 'the relay lists Bob after the POST').toEqual([s.bobFp]);
    const before = relay.seen.length;
    await removeBob(page);                                            // the APP's own path, with the APP's own gate
    await page.waitForTimeout(6_000);   // the reconcile is fire-and-forget
    gateOn = relay.seen.length > before;
    if (!gateOn) {
      expect(process.env.E2E_EXPECT_PSI_GATE, `the PSI gate is dark in this build, or the app skipped the reconcile (page console: ${JSON.stringify(relay.console)}; requests: ${JSON.stringify(relay.seen)})`).toBeFalsy();
      test.skip(true, 'the PSI gate is dark in this build, so Remove sends nothing either way: nothing to tell apart (the unit tests and the source guards cover the rules here)');
    }
    expect(deletes(relay), 'exactly one DELETE, for Bob').toEqual([s.bobFp]);
    expect(relay.list.size, 'and the relay lists nothing now').toBe(0);
  });

  test('NEG: a person the relay does NOT list (a fresh, never-exchanged contact) is removed with NO DELETE: the app asks for the owner\'s own list, and no request names the person', async ({ page }) => {
    test.skip(gateOn === false, 'the control found the PSI gate dark in this build: "no DELETE" would prove nothing');
    expect(gateOn, 'the control ran first and found out whether the gate is on').not.toBeNull();
    const relay = await mockRelay(page);
    const s = await setup(page);
    await removeBob(page);
    await page.waitForTimeout(5_000);
    expect(count(relay, 'DELETE'), `no DELETE (saw ${JSON.stringify(relay.seen)})`).toBe(0);
    expect(count(relay, 'POST')).toBe(0);
    expect(relay.seen.filter((x) => x.url.toLowerCase().includes(s.bobFp)), 'no request names Bob').toEqual([]);
  });

  test('TICK: rows the relay still lists are revoked when no consent allows them (no local record at all; a contact blocked locally); a failing GET revokes nothing and loses nothing; a refused DELETE is sent again after its window', async ({ page }) => {
    test.skip(gateOn === false, 'the PSI gate is dark in this build');
    const STALE = 'de'.repeat(32);                                   // a contact removed long ago whose DELETE never went out: no local record
    const relay = await mockRelay(page);
    const s = await setup(page);
    relay.list.add(STALE); relay.list.add(s.bobFp);
    await page.evaluate(([id]) => window.__fz.setBlocked(id as string, true), [s.bobId]);   // Bob is blocked locally; the relay still lists him
    relay.getStatus = 500;
    await page.evaluate((o) => window.__ar.tick(o), s.aliceFp);
    expect(count(relay, 'DELETE'), 'a GET that fails is UNKNOWN: nothing is revoked').toBe(0);
    expect([...relay.list].sort(), 'and nothing is lost').toEqual([s.bobFp, STALE].sort());
    relay.getStatus = 200; relay.deleteStatus = 500;
    await page.evaluate((o) => window.__ar.tick(o), s.aliceFp);
    expect(deletes(relay).sort(), 'both owed rows were tried; the relay refused').toEqual([s.bobFp, STALE].sort());
    expect(relay.list.size, 'so both are still listed, still owed').toBe(2);
    relay.deleteStatus = 200;
    await page.evaluate((o) => window.__ar.tick(o), s.aliceFp);
    expect(count(relay, 'DELETE'), 'inside the retry window nothing more is sent').toBe(2);
    await page.evaluate(() => window.__ar.reset());                  // the window passes
    await page.evaluate((o) => window.__ar.tick(o), s.aliceFp);
    expect(relay.list.size, 'now both are revoked and the relay lists nothing').toBe(0);
  });
});
