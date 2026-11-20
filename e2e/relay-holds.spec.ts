import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { seedAliceWithBob } from './fixtures/deposit-note';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * "What the relay lists" in the REAL app: the real shell, the real contact book, the real revoke check (the app's OWN tick, run by the real "Check again" button), the real recorder. The relay is a route that KEEPS A
 * LIST (GET lists it, POST adds a sender, a 2xx DELETE removes one); every request is recorded at the route.
 *  - OPENING MAKES NO REQUEST: opening the panel adds nothing to what the relay saw, and with no good read it says it could not check (never an empty list).
 *  - THE BUTTON is the app's own check: it reads the relay and the panel then shows what that read saw: a person the relay lists that the contacts do not allow is a COUNT; a contact the book allows that the relay does not list is a ROW.
 *  - REPAIR: exactly one signed POST for the row shown, then the relay lists the person and the panel says so; a contact blocked AFTER the panel was opened sends NOTHING (no add, and no new read of the relay) and says there is nothing to repair.
 *  - NO FINGERPRINT is anywhere in the panel's text or markup, with a row shown or not (the listed stranger in B3, the contact in B2). On a phone the panel fits the screen. The warning is above every Repair button.
 * The panel is shown only while the discovery gate is live (a dev build: the domain starts with "dev."); it is on when the build sets the public domain variable to a dev. domain.
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

type Seen = { method: string; url: string; body?: string };
interface Relay { list: Set<string>; seen: Seen[]; getStatus: number }

/** A relay that keeps a list, answered at the route (nothing real is reached). */
async function mockRelay(page: Page, init: { list?: string[]; getStatus?: number } = {}): Promise<Relay> {
  const relay: Relay = { list: new Set(init.list ?? []), seen: [], getStatus: init.getStatus ?? 200 };
  await page.route('**/api/satellite/allowed/**', async (route) => {
    const req = route.request(); const method = req.method();
    relay.seen.push({ method, url: req.url(), body: req.postData() ?? undefined });
    if (method === 'GET') {
      if (relay.getStatus !== 200) return route.fulfill({ status: relay.getStatus, contentType: 'application/json', body: '{}' });
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ owner_fingerprint: 'x', allowed: [...relay.list], count: relay.list.size }) });
    }
    if (method === 'POST') { relay.list.add((req.postDataJSON() as { sender_fingerprint: string }).sender_fingerprint.toLowerCase()); return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }); }
    relay.list.delete(req.url().split('/').pop()!.toLowerCase());
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  return relay;
}
const count = (r: Relay, m: string) => r.seen.filter((s) => s.method === m).length;
const deletes = (r: Relay) => r.seen.filter((s) => s.method === 'DELETE').map((s) => s.url.toLowerCase().split('/').pop());

async function setup(page: Page) {
  await genesis(page, 'Alice Lists');
  const seeded = await seedAliceWithBob(page);
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  await page.evaluate(([o, p]) => window.__fz.initApp(o, p), [seeded.aliceFp, PASS]);
  return { aliceFp: seeded.aliceFp.toLowerCase(), bobFp: seeded.bob.fingerprint.toLowerCase(), bobId: `e2e-bob-${seeded.bob.fingerprint.slice(0, 12)}` };
}

/** Identity tab -> Actions -> Lenses & vault: the panel that holds the entry. Returns the section (closed). */
async function openLensesSection(page: Page) {
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByRole('menuitem', { name: 'Lenses & vault' }).click();
  const section = page.getByTestId('relay-holds-section');
  await expect(section).toBeVisible({ timeout: 15_000 });
  return section;
}
async function openPanel(page: Page) {
  const section = await openLensesSection(page);
  await section.getByTestId('relay-holds-entry').click();
  await expect(page.getByTestId('relay-holds-panel')).toBeVisible({ timeout: 10_000 });
  return page.getByTestId('relay-holds-panel');
}
const checkAgain = async (page: Page) => { await page.getByTestId('relay-holds-refresh').click(); };

const ENTRY = 'What the relay lists';
const UNKNOWN = "We couldn't check what the relay lists right now, so nothing is shown here. Try again later.";
const UNDER_ONE = "1 person your contacts allow isn't listed at the relay, so a private match with them can't complete.";
const OVER_ONE = "The relay still lists 1 person your contacts don't allow. They'll be taken off automatically at a later check.";
const WARNING = "If you blocked or removed this person on another device, don't repair: it would list them at the relay again.";
const ALL_MATCH = 'The relay lists exactly the people your contacts allow.';
const STRANGER = 'c'.repeat(64);

const PROD = !!process.env.E2E_PROD;   // a production build: the domain is not "dev.", so the discovery gate is dark and the panel is not shown

test.describe('relay holds panel', () => {
  test.skip(PROD, 'needs the dev domain: the panel is shown only while the discovery gate is live (B7 covers the dark gate)');
  test('B1 the entry carries no digit; OPENING MAKES NO REQUEST; with no good read it says it could not check, never an empty list, and offers no Repair', async ({ page }) => {
    const relay = await mockRelay(page, { getStatus: 500 });
    await setup(page);
    const section = await openLensesSection(page);
    await expect(section.getByTestId('relay-holds-entry')).toHaveText(ENTRY);
    expect(await section.getByTestId('relay-holds-entry').innerText()).not.toMatch(/\d/);
    const before = relay.seen.length;
    await section.getByTestId('relay-holds-entry').click();
    await expect(page.getByTestId('relay-holds-line-unknown')).toHaveText(UNKNOWN);
    await page.waitForTimeout(1500);
    expect(relay.seen.length, 'opening the panel made a request').toBe(before);
    await expect(page.getByTestId('relay-holds-rows')).toHaveCount(0);
    await expect(page.getByTestId('relay-holds-line-checked')).toHaveCount(0);
  });

  test('B2 a contact the book allows that the relay does not list is a ROW with its warning above the button; Repair sends exactly ONE POST for it, says so only after the relay confirms, and the panel then reads "exactly"', async ({ page }) => {
    const relay = await mockRelay(page);
    const s = await setup(page);
    await page.evaluate(([id]) => window.__fz.setOpenVisible(id as string, true), [s.bobId]);
    await openPanel(page);
    await checkAgain(page);
    await expect(page.getByTestId('relay-holds-line-under')).toHaveText(UNDER_ONE, { timeout: 20_000 });
    const row = page.getByTestId('relay-holds-row-0');
    await expect(row).toContainText('Bob');
    expect(await page.getByTestId('relay-holds-panel').innerText(), 'a fingerprint is on screen next to a row').not.toMatch(/[0-9a-f]{40}/i);
    expect((await page.getByTestId('relay-holds-section').innerHTML()).toLowerCase().includes(s.bobFp), 'the contact\'s fingerprint is in the panel\'s markup').toBe(false);
    await expect(page.getByTestId('relay-holds-warning-0')).toHaveText(WARNING);
    const order = await row.evaluate((el) => [...el.children].map((c) => (c as HTMLElement).dataset.testid ?? c.tagName));
    expect(order.indexOf('relay-holds-warning-0')).toBeLessThan(order.indexOf('relay-holds-repair-0'));
    const postsBefore = count(relay, 'POST');
    await page.getByTestId('relay-holds-repair-0').click();
    await expect(page.getByTestId('relay-holds-notice')).toHaveText('Bob is listed at the relay again.', { timeout: 20_000 });
    expect(count(relay, 'POST') - postsBefore, 'exactly one add for the row shown').toBe(1);
    const post = relay.seen.filter((x) => x.method === 'POST').at(-1)!;
    expect(post.url.toLowerCase()).toContain(`/allowed/${s.aliceFp}`);
    expect(JSON.parse(post.body!).sender_fingerprint.toLowerCase()).toBe(s.bobFp);
    expect(count(relay, 'DELETE')).toBe(0);
    await expect(page.getByTestId('relay-holds-line-allmatch')).toHaveText(ALL_MATCH, { timeout: 25_000 });
    await expect(page.getByTestId('relay-holds-line-checked')).toBeVisible();
  });

  test('B3 a person the relay lists that the contacts do not allow is a COUNT, never named; the check takes them off; and no fingerprint is anywhere in the page', async ({ page }) => {
    const relay = await mockRelay(page, { list: [STRANGER] });
    await setup(page);
    await openPanel(page);
    await checkAgain(page);
    await expect(page.getByTestId('relay-holds-line-over')).toHaveText(OVER_ONE, { timeout: 20_000 });
    await expect.poll(() => deletes(relay), { timeout: 20_000 }).toEqual([STRANGER]);
    const html = (await page.content()).toLowerCase();
    expect(html.includes(STRANGER), 'the listed value is in the page').toBe(false);
    expect(await page.getByTestId('relay-holds-panel').innerText()).not.toMatch(/[0-9a-f]{40}/i);
    await expect(page.getByTestId('relay-holds-line-allmatch')).toHaveCount(0);
  });

  test('B4 the book is re-read AT THE PRESS: a contact blocked after the panel was opened sends NO add and reads "nothing to repair"', async ({ page }) => {
    const relay = await mockRelay(page);
    const s = await setup(page);
    await page.evaluate(([id]) => window.__fz.setOpenVisible(id as string, true), [s.bobId]);
    await openPanel(page);
    await checkAgain(page);
    await expect(page.getByTestId('relay-holds-row-0')).toBeVisible({ timeout: 20_000 });
    await page.evaluate(([id]) => window.__fz.setBlocked(id as string, true), [s.bobId]);
    const postsBefore = count(relay, 'POST');
    const getsBefore = count(relay, 'GET');
    await page.getByTestId('relay-holds-repair-0').click();
    await expect(page.getByTestId('relay-holds-notice')).toHaveText("Your contacts no longer allow Bob, so there's nothing to repair.", { timeout: 15_000 });
    await page.waitForTimeout(3500);   // longer than the revoke check's own spacing, so a stray re-read would have gone out
    expect(count(relay, 'POST') - postsBefore, 'a blocked contact was added').toBe(0);
    expect(count(relay, 'GET') - getsBefore, 'a repair that was not confirmed asked the relay again').toBe(0);
  });

  test('B5 "Check again" waits out its gap: after a press it is disabled with the SAME label', async ({ page }) => {
    await mockRelay(page);
    await setup(page);
    await openPanel(page);
    const btn = page.getByTestId('relay-holds-refresh');
    await expect(btn).toBeEnabled();
    await btn.click();
    await expect(btn).toBeDisabled();
    await expect(btn).toHaveText('Check again');
  });

  test('B6 on a PHONE the panel fits the screen (no sideways scroll), with a row and its warning shown', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await mockRelay(page);
    const s = await setup(page);
    await page.evaluate(([id]) => window.__fz.setOpenVisible(id as string, true), [s.bobId]);
    await openPanel(page);
    await checkAgain(page);
    await expect(page.getByTestId('relay-holds-row-0')).toBeVisible({ timeout: 20_000 });
    await page.getByTestId('relay-holds-row-0').scrollIntoViewIfNeeded();
    const fits = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
    expect(fits, 'sideways scroll on a phone').toBe(true);
    await page.screenshot({ path: process.env.RELAY_HOLDS_SHOT || '/tmp/relay-holds-phone.png' });
  });
});

test.describe('relay holds panel in a production build', () => {
  test.skip(!PROD, 'only in a production build, where the discovery gate is dark');

  test('B7 while the gate is DARK the panel is not shown: the Held messages entry beside it is, mine is not, and nothing asks the relay for a list', async ({ page }) => {
    const relay = await mockRelay(page);
    await genesis(page, 'Alice Dark');
    await page.getByRole('tab', { name: 'Identity', exact: true }).click();
    await page.getByTestId('card-actions-toggle').click();
    await page.getByRole('menuitem', { name: 'Lenses & vault' }).click();
    await expect(page.getByTestId('held-section')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('relay-holds-section')).toHaveCount(0);
    await page.waitForTimeout(2000);
    expect(relay.seen.length, 'a dark gate still asked the relay for something').toBe(0);
  });
});
