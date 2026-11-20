import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { seedAliceWithBob } from './fixtures/deposit-note';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * A pair is confirmed only while the confirm was made for the beacon key this device holds NOW, in the REAL app's store: the real encrypted confirmed row, the real contact book, and the production port
 * the beacon client asks (createBeaconConfirmedPort). Confirmed at generation N, then the held key replaced by N+1 -> not confirmed, until a live confirm records N+1.
 * It runs on the dev server and needs no PSI gate: nothing here sends anything.
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

test('a pair confirmed at generation N is NOT confirmed once the held key is replaced by N+1, until a live confirm at N+1; the real store, the production port', async ({ page }) => {
  test.setTimeout(180_000);
  await genesis(page, 'Alice Confirms');
  const seeded = await seedAliceWithBob(page);
  await page.addScriptTag({ content: bundle('e2e/helpers/beacon-confirmed-harness.ts') });
  await page.evaluate((p) => window.__bc.init(p), PASS);
  const owner = seeded.aliceFp;
  const bobFp = seeded.bob.fingerprint.toLowerCase();
  const bobId = `e2e-bob-${seeded.bob.fingerprint.slice(0, 12)}`;
  const bc = {
    set: (key: string, g: number) => page.evaluate(([id, k, n]) => window.__bc.setBeaconKey(id as string, k as string, n as number), [bobId, key, g]),
    confirm: (contactFp: string, g: number) => page.evaluate(([o, f, n]) => window.__bc.confirm(o as string, f as string, n as number), [owner, contactFp, g]),
    ok: (pairId: string): Promise<boolean> => page.evaluate(([o, p]) => window.__bc.isConfirmed(o as string, p as string), [owner, pairId]),
  };
  const pairId: string = await page.evaluate((fp) => window.__bc.pairId(fp), bobFp);
  expect(pairId).toMatch(/^[0-9a-f]{64}$/);

  // the contact holds a key at generation 5
  await bc.set('KEY-AT-5', 5);
  const held = (await page.evaluate((o) => window.__bc.held(o), owner)).filter((c) => c.beacon_key_generation !== undefined);
  expect(held, 'PRECONDITION: the contact book holds the key at generation 5, under the fingerprint the pair id is derived from').toEqual([{ id: bobId, fingerprint: bobFp, beacon_public_key: 'KEY-AT-5', beacon_key_generation: 5 }]);
  expect(await bc.ok(pairId), 'no confirm has been recorded: not confirmed').toBe(false);
  await bc.confirm(bobFp, 5);
  expect(await bc.ok(pairId), 'CONTROL: confirmed at 5, holding 5').toBe(true);

  // the held key is replaced by generation 6: the confirm made for 5 does not carry over
  await bc.set('KEY-AT-6', 6);
  expect(await bc.ok(pairId), 'replaced by 6: NOT confirmed').toBe(false);

  // a live confirm records 6 (monotone upward): confirmed again
  await bc.confirm(bobFp, 6);
  expect(await bc.ok(pairId), 'confirmed at 6, holding 6').toBe(true);

  // a held key that went BACK to 5 is not the confirmed one either (the stored entry stays at 6)
  await bc.set('KEY-AT-5', 5);
  expect(await bc.ok(pairId), 'held 5, confirmed 6: NOT confirmed').toBe(false);
  await bc.set('KEY-AT-6', 6);
  expect(await bc.ok(pairId), 'held 6 again: confirmed').toBe(true);

  // a contact with no pair (no key, no fingerprint) in the book does not stop the scan from finding the right contact
  await page.evaluate((o) => window.__bc.addKeyless(o), owner);
  expect(await bc.ok(pairId), 'a keyless contact in the book: still found, still confirmed').toBe(true);

  // a pair that belongs to no contact is not confirmed, even with a confirmed row for it
  const strangerFp = 'ab'.repeat(32);
  await bc.confirm(strangerFp, 6);
  const strangerPair: string = await page.evaluate((fp) => window.__bc.pairId(fp), strangerFp);
  expect(strangerPair).not.toBe(pairId);
  expect(await bc.ok(strangerPair), 'a confirmed row for a pair no contact has: NOT confirmed').toBe(false);

  // a locked session cannot read the row or the contacts: fail closed
  await page.evaluate(() => window.__bc.lock());
  expect(await bc.ok(pairId), 'locked: NOT confirmed (fail closed)').toBe(false);
});
