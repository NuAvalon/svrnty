import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * The hold's AGE LIMIT, in a REAL browser: the real encrypted notes store (IndexedDB + AES-GCM), nothing stubbed, and the real held-count row. The unit tests hold the rules (held-age.test.ts) and static
 * pins hold the wiring (held-age-wiring.test.ts); this proves the REAL store applies them:
 *  - the limit and the grace, AT and one millisecond either side: a first sweep past the limit only STAMPS; the note is deleted only a full grace after the stamp;
 *  - unknown age (no held_at, or junk) is stamped and kept; a held_at in the future stays;
 *  - a wrong device date that PERSISTS deletes nothing for a week; a clock put back clears the mark;
 *  - an ordinary note (even one carrying look-alike stamps), an outbound note and a look-alike held value are never touched;
 *  - a limit of 0 is the off switch: nothing deleted, nothing stamped as expiring;
 *  - every delete is COUNTED: the count row equals the full scan after the sweep, and a held write racing a sweep loses no count;
 *  - a note that can no longer be read is skipped, never deleted;
 *  - and the unlock path really runs it (the count row first, then the sweep) on the real clock.
 */
const OWNER = 'owner-hold-age-e2e';
const A = 'ab'.repeat(32);
const DAY = 86_400_000;
const NOW = Date.parse('2026-06-01T12:00:00.000Z');
const iso = (ms: number): string => new Date(ms).toISOString();

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function setup(page: Page, mode: 'reconciled' | 'plain') {
  await page.goto('/');
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  if (mode === 'reconciled') expect(await page.evaluate((o) => window.__fz.initReconciled(o), OWNER)).toBe('ok');
  else await page.evaluate((o) => window.__fz.init(o), OWNER);
}

const mkThread = (id: string, held = false) => ({ thread_id: id, kind: 'direct', participants: [], created_at: '2026-01-01T00:00:00.000Z', last_activity_at: '2026-01-02T00:00:00.000Z', retention: { expires_at: null }, ...(held ? { held: true } : {}) });
const mkNote = (id: string, threadId: string, from: string, over: Record<string, unknown> = {}) => ({
  note_id: id, thread_id: threadId, direction: 'inbound', from_fingerprint: from, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: `body of ${id}`,
  participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...over,
});
const heldNote = (id: string, over: Record<string, unknown> = {}) => mkNote(id, 'S-held', A, { held: true, ...over });
const put = (page: Page, n: unknown) => page.evaluate((x) => window.__fz.putNote(x as never), n);
const putThread = (page: Page, t: unknown) => page.evaluate((x) => window.__fz.putThread(x as never), t);
const get = (page: Page, id: string) => page.evaluate((x) => window.__fz.get(x), id) as Promise<Record<string, unknown> | null>;
const sweep = (page: Page, nowMs: number, limits?: { limitDays?: number; graceDays?: number }) => page.evaluate((a) => window.__fz.sweep(a.nowMs, a.limits), { nowMs, limits });
const held = (page: Page, fp: string) => page.evaluate((f) => window.__fz.held(f), fp);
const scan = (page: Page, fp: string) => page.evaluate((f) => window.__fz.countHeld(f), fp);
async function expectRowEqualsScan(page: Page, who: string[], why: string) {
  for (const fp of who) expect({ why, fp: fp.slice(0, 4), row: await held(page, fp) }).toEqual({ why, fp: fp.slice(0, 4), row: { count: await scan(page, fp) } });
}
const stampsOf = async (page: Page, id: string) => { const n = await get(page, id); return n ? { held_at: n.held_at, expiry_seen_at: n.expiry_seen_at } : null; };

test('D1 the limit and the grace in the real store, AT and one millisecond either side: first sweep stamps only, the delete comes a full grace later, the count row follows every delete', async ({ page }) => {
  test.setTimeout(120_000);
  await setup(page, 'reconciled');
  await putThread(page, mkThread('S-held', true));
  await putThread(page, mkThread('S-ord'));
  const L = 30 * DAY;
  const seeds: Array<[string, Record<string, unknown>]> = [
    ['n29', { held_at: iso(NOW - 29 * DAY) }], ['n30m', { held_at: iso(NOW - (L - 1)) }], ['n30', { held_at: iso(NOW - L) }], ['n30p', { held_at: iso(NOW - (L + 1)) }], ['n31', { held_at: iso(NOW - 31 * DAY) }],
    ['legacy', {}], ['junk', { held_at: 'not a date' }], ['future', { held_at: iso(NOW + DAY) }],
  ];
  for (const [id, over] of seeds) await put(page, heldNote(id, over));
  // not held, so never touched: an ordinary inbound note and an outbound one, both carrying look-alike stamps that WOULD delete a held note
  const stamps = { held_at: iso(NOW - 400 * DAY), expiry_seen_at: iso(NOW - 90 * DAY) };
  await put(page, mkNote('ord', 'S-ord', A, stamps));
  await put(page, mkNote('out', 'S-ord', A, { direction: 'outbound', ...stamps }));
  const ordBefore = JSON.stringify([await get(page, 'ord'), await get(page, 'out')]);
  await expectRowEqualsScan(page, [A], 'seeded');
  expect(await held(page, A)).toEqual({ count: 8 });

  // sweep 1: nothing is deleted. The three at or past the limit are STAMPED; unknown age gets its clock started; the rest are untouched.
  expect(await sweep(page, NOW)).toEqual({ deleted: 0, stamped: 5, cleared: 0, kept: 3, skipped: 0 });
  for (const id of ['n30', 'n30p', 'n31']) expect(await stampsOf(page, id), id).toMatchObject({ expiry_seen_at: iso(NOW) });
  for (const id of ['n29', 'n30m', 'future']) expect((await stampsOf(page, id))?.expiry_seen_at, id).toBeUndefined();
  for (const id of ['legacy', 'junk']) expect(await stampsOf(page, id), id).toEqual({ held_at: iso(NOW), expiry_seen_at: undefined });
  expect((await stampsOf(page, 'n30'))?.held_at, 'the age clock is not restarted by the expiry stamp').toBe(iso(NOW - L));
  await expectRowEqualsScan(page, [A], 'after sweep 1');
  expect(await held(page, A)).toEqual({ count: 8 });

  // sweep 2, one millisecond short of the grace: still nothing is deleted
  const s2 = await sweep(page, NOW + 7 * DAY - 1);
  expect(s2.deleted).toBe(0);
  for (const id of ['n30', 'n30p', 'n31']) expect(await get(page, id), `${id} still there`).not.toBeNull();

  // sweep 3, exactly the grace: the three stamped notes go, and the count row drops with them in the same step
  const s3 = await sweep(page, NOW + 7 * DAY);
  expect(s3.deleted).toBe(3);
  for (const id of ['n30', 'n30p', 'n31']) expect(await get(page, id), `${id} deleted`).toBeNull();
  for (const id of ['n29', 'n30m', 'legacy', 'junk', 'future']) expect(await get(page, id), `${id} kept`).not.toBeNull();
  expect(await held(page, A)).toEqual({ count: 5 });
  await expectRowEqualsScan(page, [A], 'after the deletes');
  expect(JSON.stringify([await get(page, 'ord'), await get(page, 'out')]), 'an ordinary and an outbound note are byte-for-byte what they were, through three sweeps').toBe(ordBefore);
});

test('D2 a wrong device date that PERSISTS: +1 year stamps only, nothing is deleted for a full grace, then it is (and a clock put right in time clears the mark and deletes nothing)', async ({ page }) => {
  test.setTimeout(120_000);
  await setup(page, 'reconciled');
  await putThread(page, mkThread('S-held', true));
  for (const id of ['y1', 'y2', 'y3']) await put(page, heldNote(id, { held_at: iso(NOW - DAY) }));
  const JUMP = NOW + 365 * DAY;
  expect(await sweep(page, JUMP)).toMatchObject({ deleted: 0, stamped: 3 });
  expect((await sweep(page, JUMP + 7 * DAY - 1)).deleted).toBe(0);
  // the clock is put right BEFORE the grace ends: the marks are cleared, nothing is deleted
  expect(await sweep(page, NOW)).toMatchObject({ deleted: 0, cleared: 3 });
  for (const id of ['y1', 'y2', 'y3']) expect((await stampsOf(page, id))?.expiry_seen_at, id).toBeUndefined();
  await expectRowEqualsScan(page, [A], 'after the clock was put right');
  expect(await held(page, A)).toEqual({ count: 3 });
  // the wrong date comes back and STAYS: stamp, then a full grace, then deleted
  expect(await sweep(page, JUMP)).toMatchObject({ deleted: 0, stamped: 3 });
  expect((await sweep(page, JUMP + 7 * DAY)).deleted).toBe(3);
  expect(await held(page, A)).toEqual({ count: 0 });
  await expectRowEqualsScan(page, [A], 'after the persistent wrong date finally deleted them');
});

test('D3 a held_at in the FUTURE stays, a mark in the future never deletes, and an unreadable mark is made again, not trusted', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('S-held', true));
  await put(page, heldNote('f1', { held_at: iso(NOW + 30 * DAY) }));
  await put(page, heldNote('f2', { held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW + DAY) }));
  await put(page, heldNote('f3', { held_at: iso(NOW - 40 * DAY), expiry_seen_at: 'garbage' }));
  await put(page, heldNote('f4', { held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW + 30 * DAY) }));   // a mark far MORE than a grace ahead: only "it is in the future" keeps it, not its distance
  // swept at NOW: f1's held_at is 30 days ahead, and f2's mark (NOW + 1 day) is still ahead of the clock, so neither can delete anything; f3's mark is junk, so it is made again from the owner's clock
  expect(await sweep(page, NOW)).toMatchObject({ deleted: 0 });
  expect(await get(page, 'f1')).not.toBeNull();
  expect(await get(page, 'f2')).not.toBeNull();
  expect((await stampsOf(page, 'f2'))?.expiry_seen_at, 'a mark in the future is left as it is').toBe(iso(NOW + DAY));
  expect(await stampsOf(page, 'f4'), 'a mark 30 days ahead is left as it is, and the note is kept').toEqual({ held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW + 30 * DAY) });
  expect((await stampsOf(page, 'f3'))?.expiry_seen_at, 'the garbage mark was replaced by a real one').toBe(iso(NOW));
  // and once the clock passes that future mark by a full grace, f2 is deleted like any other (control: the guard is the future mark, nothing else)
  expect((await sweep(page, NOW + DAY + 7 * DAY)).deleted).toBeGreaterThanOrEqual(1);
  expect(await get(page, 'f2')).toBeNull();
  expect(await get(page, 'f4'), 'and the far-future mark still holds its note').not.toBeNull();
  await expectRowEqualsScan(page, [A], 'after');
});

test('D4 a limit of 0 is the OFF SWITCH in the real store: nothing deleted, nothing stamped as expiring, not even a legacy row\'s clock', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('S-held', true));
  await put(page, heldNote('o1', { held_at: iso(NOW - 400 * DAY), expiry_seen_at: iso(NOW - 90 * DAY) }));
  await put(page, heldNote('o2', { held_at: iso(NOW - 400 * DAY) }));
  await put(page, heldNote('o3', {}));
  const before = JSON.stringify([await get(page, 'o1'), await get(page, 'o2'), await get(page, 'o3')]);
  expect(await sweep(page, NOW + 5 * 365 * DAY, { limitDays: 0 })).toEqual({ deleted: 0, stamped: 0, cleared: 0, kept: 3, skipped: 0 });
  expect(JSON.stringify([await get(page, 'o1'), await get(page, 'o2'), await get(page, 'o3')])).toBe(before);
  expect(await held(page, A)).toEqual({ count: 3 });
  // control: the SAME notes ARE deleted with the real limit, so the switch is what held them
  expect(await sweep(page, NOW + 5 * 365 * DAY)).toMatchObject({ deleted: 1 });
});

test('D5 a held write racing the sweep loses no count: the row equals the scan, whatever order they land in', async ({ page }) => {
  test.setTimeout(180_000);
  await setup(page, 'reconciled');
  await putThread(page, mkThread('S-held', true));
  for (let round = 0; round < 2; round++) {
    for (let i = 0; i < 30; i++) await put(page, heldNote(`old-${round}-${i}`, { held_at: iso(NOW - 60 * DAY), expiry_seen_at: iso(NOW - 20 * DAY) }));
    const out = await page.evaluate(async (a) => {
      const mk = (id: string) => ({ note_id: id, thread_id: 'S-held', direction: 'inbound', from_fingerprint: a.fp, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: id, participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true, held_at: new Date(a.now).toISOString() });
      const sweeping = window.__fz.sweep(a.now, undefined);
      const writes: Promise<unknown>[] = [];
      for (let i = 0; i < 20; i++) writes.push(window.__fz.putNote(mk(`new-${a.round}-${i}`) as never));
      await Promise.all(writes);
      return sweeping;
    }, { fp: A, now: NOW, round });
    expect(out.deleted, `round ${round}: every expired note went`).toBe(30);
    await expectRowEqualsScan(page, [A], `round ${round}: a write racing the sweep`);
    expect(await held(page, A)).toEqual({ count: 20 * (round + 1) });
  }
});

test('D6 a held note that can no longer be READ is skipped, never deleted; the readable expired ones next to it are', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('S-held', true));
  for (const id of ['r1', 'r2', 'r3']) await put(page, heldNote(id, { held_at: iso(NOW - 60 * DAY), expiry_seen_at: iso(NOW - 20 * DAY) }));
  await page.evaluate(() => window.__fz.corruptNote('r2', 'S-held'));
  const s = await sweep(page, NOW);
  expect(s.deleted).toBe(2);
  const raw = await page.evaluate(() => window.__fz.raw());
  const ids = raw.filter((r) => r.store === 'notes').map((r) => r.plaintext.note_id);
  expect(ids, 'the unreadable row is still at rest').toEqual(['r2']);
});

test('D7 the UNLOCK path runs it on the real clock: the count row is put right first, then the expired held notes go and the young ones stay', async ({ page }) => {
  test.setTimeout(120_000);
  await setup(page, 'plain');
  const real = await page.evaluate(() => Date.now());
  await putThread(page, mkThread('S-held', true));
  for (let i = 0; i < 4; i++) await put(page, heldNote(`old-${i}`, { held_at: iso(real - 90 * DAY), expiry_seen_at: iso(real - 30 * DAY) }));
  for (let i = 0; i < 3; i++) await put(page, heldNote(`young-${i}`, { held_at: iso(real - 5 * DAY) }));
  await put(page, heldNote('legacy', {}));
  expect(await scan(page, A)).toBe(8);
  // the next unlock, the way the app does it (the background reconcile and sweep run; nobody waits for them)
  await page.evaluate((o) => window.__fz.initOnly(o), OWNER);
  await expect.poll(() => scan(page, A), { timeout: 30_000 }).toBe(4);
  await expectRowEqualsScan(page, [A], 'after the unlock sweep');
  for (let i = 0; i < 4; i++) expect(await get(page, `old-${i}`)).toBeNull();
  for (let i = 0; i < 3; i++) expect(await get(page, `young-${i}`)).not.toBeNull();
  expect((await stampsOf(page, 'legacy'))?.held_at, 'a legacy row got its clock started, and was not deleted').toBeTruthy();
});
