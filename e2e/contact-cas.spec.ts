import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';

/**
 * Contact writes are a compare-and-swap, and writes that protect the owner take a per-contact Web Lock, in a REAL browser: real IndexedDB, the
 * real encrypted contact rows and book manifest, real navigator.locks across two tabs of one context.
 *
 * Writes are driven from the page through a small esbuild-bundled harness that calls the app's own store functions (updateContact, addContact,
 * the unlock verification); nothing is stubbed. The integrity check is the app's own: the manifest is verified when the vault unlocks, and a
 * mismatch sets the book to 'corrupt' (which prompts a restore).
 *
 * CAS_CONTROL=1 runs only the first two tests (they need nothing from the change), so the same spec can be pointed at the tree BEFORE the change.
 */

const PASS = 'e2e-passphrase-1234';
const OWNER = 'owner-cas-e2e';
const CONTROL = !!process.env.CAS_CONTROL;

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src'], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });

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

/** Unlock again, which re-verifies the book manifest, and read the app's own integrity flag. */
async function integrityAfterUnlock(page: Page): Promise<'ok' | 'corrupt'> {
  await page.evaluate((p) => window.__cas.init(p), PASS);
  return page.evaluate((o) => window.__cas.integrity(o), OWNER);
}

async function setup(page: Page) {
  await genesis(page, 'Casey');
  await page.addScriptTag({ content: bundle('e2e/helpers/contact-cas-harness.ts') });
  await page.evaluate((p) => window.__cas.init(p), PASS);
}

test('concurrent writes to ONE contact all land: no write overwrites another', async ({ page }) => {
  test.setTimeout(150_000);
  await setup(page);
  const a = await page.evaluate((o) => window.__cas.add(o, 'A'), OWNER);
  // four writes to one contact at once, each adding its own tag to the tag list it read
  const out = await page.evaluate(([id]) => window.__cas.together([1, 2, 3, 4].map((i) => ({ kind: 'tag' as const, id, tag: `t${i}` }))), [a]);
  const tags = await page.evaluate(([id]) => window.__cas.tags(id), [a]);
  expect(out.filter((o) => !o.ok), 'no write may fail with a conflict at this level of contention').toEqual([]);
  expect([...tags].sort(), 'every tag survived: no write overwrote another').toEqual(['t1', 't2', 't3', 't4']);
});

test('with version changes on other contacts and a new contact all at once, the book manifest still verifies on the next unlock', async ({ page }) => {
  test.setTimeout(150_000);
  await setup(page);
  const [a, b, c] = [
    await page.evaluate((o) => window.__cas.add(o, 'A'), OWNER),
    await page.evaluate((o) => window.__cas.add(o, 'B'), OWNER),
    await page.evaluate((o) => window.__cas.add(o, 'C'), OWNER),
  ];
  expect(await integrityAfterUnlock(page), 'control: the book verifies before any concurrent write').toBe('ok');
  // at once: a version bump on B, a version bump on C, a tag on A, and a new contact: each of the first two and the add changes the manifest
  const out = await page.evaluate(([x, y, z, o]) => window.__cas.together([
    { kind: 'bump', id: y }, { kind: 'bump', id: z }, { kind: 'tag', id: x, tag: 't5' }, { kind: 'add', owner: o, name: 'D' },
  ]), [a, b, c, OWNER]);
  expect(out.filter((o) => !o.ok), 'none of the four failed').toEqual([]);
  expect(await page.evaluate(([id]) => window.__cas.version(id), [b]), 'B\'s version bump landed').toBe(1);
  expect(await page.evaluate(([id]) => window.__cas.version(id), [c]), 'C\'s version bump landed').toBe(1);
  expect(await page.evaluate((o) => window.__cas.count(o), OWNER)).toBe(4);
  // the app's own check: unlock again and let it verify the manifest against the book
  expect(await integrityAfterUnlock(page), 'the manifest matches the book after concurrent version changes and an add').toBe('ok');
});

test('two tabs: a poll in one tab defers a contact the other tab is protecting, and a protecting write lands against a polling tab', async ({ page, context }) => {
  test.skip(CONTROL, 'needs the safety lock, which the tree before the change does not have');
  test.setTimeout(180_000);
  await genesis(page, 'Casey');
  const src = bundle('e2e/helpers/contact-cas-locks-harness.ts');
  await page.addScriptTag({ content: src });
  await page.evaluate((p) => window.__casl.init(p), PASS);
  const a = await page.evaluate((o) => window.__casl.add(o, 'A'), OWNER);
  const b = await page.evaluate((o) => window.__casl.add(o, 'B'), OWNER);

  const page2 = await context.newPage();
  await page2.goto('/');
  await page2.addScriptTag({ content: src });
  await page2.evaluate((p) => window.__casl.init(p), PASS);
  expect(await page.evaluate(() => window.__casl.lockSupported())).toBe(true);
  expect(await page2.evaluate(() => window.__casl.lockSupported())).toBe(true);

  // 1. tab 1 protects A; tab 2's poll defers A, still writes B, and writes A once tab 1 is done
  await page.evaluate(([id]) => window.__casl.hold(id, 2500), [a]); // resolves once the lock is granted
  expect(await page2.evaluate(([id]) => window.__casl.poll(id, 'poll-during'), [a])).toEqual({ deferred: true });
  expect(await page2.evaluate(([id]) => window.__casl.poll(id, 'poll-other'), [b])).toEqual({ deferred: false });
  expect(await page.evaluate(([id]) => window.__casl.tags(id), [a])).not.toContain('poll-during');
  expect(await page.evaluate(([id]) => window.__casl.tags(id), [b])).toContain('poll-other');
  await expect.poll(async () => (await page2.evaluate(([id]) => window.__casl.poll(id, 'poll-after'), [a]) as { deferred: boolean }).deferred, { timeout: 10_000, intervals: [250] }).toBe(false);
  const afterHold = await page.evaluate(([id]) => window.__casl.tags(id), [a]);
  expect(afterHold).toContain('poll-after');
  expect(afterHold, "the deferred poll's change was not applied while the contact was protected").not.toContain('poll-during');

  // 2. tab 2 polls A in a tight loop; tab 1 makes a series of protecting writes to A. Each must land. The run must also show the lock was
  //    really contended (some poll writes deferred), or it proved nothing.
  await page2.evaluate(([id]) => {
    (window as unknown as { __loop: Promise<unknown[]> }).__loop = (async () => {
      const out: unknown[] = [];
      for (let i = 0; i < 400; i++) { out.push(await window.__casl.poll(id, `p${i}`)); await new Promise((r) => setTimeout(r, 0)); }
      return out;
    })();
  }, [a]);
  const results: unknown[] = [];
  for (let i = 0; i < 12; i++) {
    results.push(await page.evaluate(([id, n]) => window.__casl.safety(id, `SAFETY${n}`), [a, i] as const));
    await page.waitForTimeout(15);
  }
  expect(results.filter((r) => !(r as { ok: boolean }).ok), 'every protecting write landed (none failed with a conflict)').toEqual([]);
  const outs = (await page2.evaluate(() => (window as unknown as { __loop: Promise<Array<{ deferred?: boolean; error?: string }>> }).__loop));
  expect(outs.filter((o) => o.error), 'no poll write failed').toEqual([]);
  const final = await page.evaluate(([id]) => window.__casl.tags(id), [a]);
  for (let i = 0; i < 12; i++) expect(final).toContain(`SAFETY${i}`);
  const applied = outs.map((o, i) => (o.deferred === false ? `p${i}` : null)).filter(Boolean) as string[];
  const deferred = outs.filter((o) => o.deferred === true).length;
  expect(deferred, 'the lock was really contended: some poll writes were deferred while a protecting write held the contact').toBeGreaterThan(0);
  for (const t of applied) expect(final, `poll write ${t} that ran was kept`).toContain(t);
  console.log(`two-tab loop: ${applied.length} poll writes applied, ${deferred} deferred while the contact was protected, 12 protecting writes landed`);
});
