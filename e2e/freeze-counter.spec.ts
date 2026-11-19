import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { HELD_COUNTS_BUCKET, sealedShape } from '../src/lib/messaging/held-counts';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * The held-count row, in a REAL browser: the real encrypted notes store (IndexedDB + AES-GCM), nothing stubbed. The unit tests hold the pure rules (held-counts.test.ts) and static pins hold the
 * wiring (held-counts-wiring.test.ts); this proves the REAL store keeps the row right:
 *  - the row says exactly what the full scan says, after every write, case-insensitively, and an outbound or ordinary note never counts;
 *  - many writes at once (and a reconcile racing writes) never lose a count, and a NAIVE read-await-write counter does, so this harness can see a loss;
 *  - an absent or corrupt row is never read as a number: the cap check falls back to the scan and is right, then a reconcile puts the row right;
 *  - the sealed row's size does not change with how many senders are frozen, and the settings store holds exactly one constant key for it;
 *  - a thread delete keeps held notes and changes no count;
 *  - and the point of it all: the per-arrival check is an order of magnitude cheaper than the scan.
 */
const OWNER = 'owner-freeze-counter-e2e';
const A = 'ab'.repeat(32);
const B = 'cd'.repeat(32);
const C = 'ef'.repeat(32);

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function setup(page: Page, mode: 'reconciled' | 'plain') {
  await page.goto('/');
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  if (mode === 'reconciled') expect(await page.evaluate((o) => window.__fz.initReconciled(o), OWNER)).toBe('ok');
  else await page.evaluate((o) => window.__fz.init(o), OWNER);
}

/** Notes are built INSIDE the page so a big seed does not travel through the test runner. */
async function seed(page: Page, spec: { threads: number; ordinary: number; held: number; heldFrom: string }) {
  await page.evaluate(async (a) => {
    const base = '2026-01-02T00:00:00.000Z';
    const th = (id: string, held: boolean) => ({ thread_id: id, kind: 'direct', participants: [], created_at: '2026-01-01T00:00:00.000Z', last_activity_at: base, retention: { expires_at: null }, ...(held ? { held: true } : {}) });
    const nt = (id: string, t: string, from: string, held: boolean) => ({ note_id: id, thread_id: t, direction: 'inbound', from_fingerprint: from, to_fingerprints: [], sent_at: base, body: `body ${id}`, participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...(held ? { held: true } : {}) });
    for (let t = 0; t < a.threads; t++) await window.__fz.putThread(th(`S-ord-${t}`, false) as never);
    await window.__fz.putThread(th('S-held', true) as never);
    for (let i = 0; i < a.ordinary; i++) await window.__fz.putNote(nt(`s-ord-${i}`, `S-ord-${i % a.threads}`, 'cd'.repeat(32), false) as never);
    for (let i = 0; i < a.held; i++) await window.__fz.putNote(nt(`s-held-${i}`, 'S-held', a.heldFrom, true) as never);
  }, spec);
}

const mkThread = (id: string, held = false) => ({ thread_id: id, kind: 'direct', participants: [], created_at: '2026-01-01T00:00:00.000Z', last_activity_at: '2026-01-02T00:00:00.000Z', retention: { expires_at: null }, ...(held ? { held: true } : {}) });
const mkNote = (id: string, threadId: string, from: string, over: Record<string, unknown> = {}) => ({
  note_id: id, thread_id: threadId, direction: 'inbound', from_fingerprint: from, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: `body of ${id}`,
  participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...over,
});
const put = (page: Page, n: unknown) => page.evaluate((x) => window.__fz.putNote(x as never), n);
const putThread = (page: Page, t: unknown) => page.evaluate((x) => window.__fz.putThread(x as never), t);
const held = (page: Page, fp: string) => page.evaluate((f) => window.__fz.held(f), fp);
const scan = (page: Page, fp: string) => page.evaluate((f) => window.__fz.countHeld(f), fp);
/** The row must say what the scan says, for these senders. */
async function expectRowEqualsScan(page: Page, who: string[], why: string) {
  for (const fp of who) expect({ why, fp: fp.slice(0, 4), row: await held(page, fp) }).toEqual({ why, fp: fp.slice(0, 4), row: { count: await scan(page, fp) } });
}

test('C1 the row says what the full scan says after EVERY write: held inbound counts (case-insensitively), ordinary and held-outbound notes do not', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('T1'));
  await putThread(page, mkThread('TH', true));
  const steps: Array<[string, unknown]> = [
    ['held from A', mkNote('n1', 'TH', A, { held: true })],
    ['held from A, upper-case fingerprint', mkNote('n2', 'TH', A.toUpperCase(), { held: true })],
    ['held from B', mkNote('n3', 'TH', B, { held: true })],
    ['ordinary from A', mkNote('n4', 'T1', A)],
    ['held but OUTBOUND from A', mkNote('n5', 'T1', A, { held: true, direction: 'outbound' })],
  ];
  for (const [why, n] of steps) { await put(page, n); await expectRowEqualsScan(page, [A, B, C], why); }
  expect(await held(page, A)).toEqual({ count: 2 });
  expect(await held(page, B)).toEqual({ count: 1 });
  expect(await held(page, C)).toEqual({ count: 0 });
});

test('C2 many writes at once never lose a count (and a naive read-await-write counter does, so this harness can see a loss)', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('TH', true));
  for (let round = 1; round <= 3; round++) {
    await page.evaluate(async (r) => {
      const mk = (id: string, from: string) => ({ note_id: id, thread_id: 'TH', direction: 'inbound', from_fingerprint: from, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: id, participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true });
      const ops: Promise<unknown>[] = [];
      for (let i = 0; i < 25; i++) { ops.push(window.__fz.putNote(mk(`r${r}-a-${i}`, 'ab'.repeat(32)) as never)); ops.push(window.__fz.putNote(mk(`r${r}-b-${i}`, 'cd'.repeat(32)) as never)); }
      await Promise.all(ops);
    }, round);
    expect(await held(page, A)).toEqual({ count: 25 * round });
    expect(await held(page, B)).toEqual({ count: 25 * round });
    await expectRowEqualsScan(page, [A, B], `after round ${round}`);
  }
  const naive = await page.evaluate(() => window.__fz.naiveCounter(25));
  expect(naive, 'the control: a naive counter run 25 at once must LOSE updates').toBeLessThan(25);
});

test('C3 a row that is replaced or redelivered moves the count by what changed, not by one: same held note again = no change; held -> ordinary = -1; held from A -> held from B = A -1, B +1', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('TH', true));
  expect(await put(page, mkNote('x', 'TH', A, { held: true })), 'a first write reports "created"').toBe(true);
  expect(await held(page, A)).toEqual({ count: 1 });
  expect(await page.evaluate((n) => window.__fz.putNote(n as never), mkNote('x', 'TH', A, { held: true })), 'a redelivery reports "not created"').toBe(false);
  expect(await held(page, A)).toEqual({ count: 1 });
  await put(page, mkNote('x', 'TH', A));
  expect(await held(page, A)).toEqual({ count: 0 });
  await expectRowEqualsScan(page, [A], 'held replaced by an ordinary note');
  await put(page, mkNote('x', 'TH', A, { held: true }));
  expect(await held(page, A)).toEqual({ count: 1 });
  await put(page, mkNote('x', 'TH', B, { held: true }));
  expect(await held(page, A)).toEqual({ count: 0 });
  expect(await held(page, B)).toEqual({ count: 1 });
  await expectRowEqualsScan(page, [A, B], 'held from A replaced by held from B');
});

test('C4 an ABSENT row is never read as a number: the cap check falls back to the scan and is right, a held write leaves the row never wrong, and a reconcile puts it right', async ({ page }) => {
  await setup(page, 'plain');
  expect(await held(page, A)).toEqual({ fallback: 'absent' });
  await putThread(page, mkThread('TH', true));
  for (let i = 1; i <= 3; i++) {
    await put(page, mkNote(`h${i}`, 'TH', A, { held: true }));
    const now = await held(page, A);
    // The write marks the row dirty and a reconcile is scheduled in the background, which may already have healed it: either way it is never a WRONG number.
    expect(now.hasOwnProperty('fallback') ? (now as { fallback: string }).fallback : (now as { count: number }).count === i).toBeTruthy();
    expect(await page.evaluate((f) => window.__fz.fast(f), A), 'the cap check is right while the row is not usable').toBe(i);
  }
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect(await held(page, A)).toEqual({ count: 3 });
  await expectRowEqualsScan(page, [A, B], 'after the reconcile');
});

test('C5 a CORRUPT row is never read as a number: unreadable, the cap check is still right, and the reconcile replaces it', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('TH', true));
  for (let i = 0; i < 4; i++) await put(page, mkNote(`c${i}`, 'TH', A, { held: true }));
  expect(await held(page, A)).toEqual({ count: 4 });
  await page.evaluate(() => window.__fz.corruptSetting('held_counts:v1'));
  expect(await held(page, A)).toEqual({ fallback: 'unreadable' });
  expect(await page.evaluate((f) => window.__fz.fast(f), A), 'right, not 0 and not the cap').toBe(4);
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect(await held(page, A)).toEqual({ count: 4 });
  await page.evaluate(() => window.__fz.corruptSetting('held_counts:v1'));
  await put(page, mkNote('c-new', 'TH', A, { held: true }));
  const after = await held(page, A);
  expect(after.hasOwnProperty('fallback') || (after as { count: number }).count === 5, 'a write over a corrupt row never leaves a wrong number').toBeTruthy();
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect(await held(page, A)).toEqual({ count: 5 });
});

test('C6 the sealed row is the SAME size whether nobody, one sender or thirty are frozen, and the settings store holds exactly one constant key for it', async ({ page }) => {
  await setup(page, 'reconciled');
  const keys = async () => (await page.evaluate(() => window.__fz.settingsRows())).map((r) => r.key);
  expect(await keys()).toEqual(['held_counts:v1', 'notes_encryption_salt']);
  const size = async () => (await page.evaluate(() => window.__fz.settingsRows())).find((r) => r.key === 'held_counts:v1')!;
  const none = await size();
  expect(none.sealed).toBe(true);
  await putThread(page, mkThread('TH', true));
  await put(page, mkNote('z1', 'TH', A, { held: true }));
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect((await size()).encBytes).toBe(none.encBytes);
  for (let i = 0; i < 30; i++) await put(page, mkNote(`z-many-${i}`, 'TH', i.toString(16).padStart(64, '0'), { held: true }));
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect((await size()).encBytes, 'thirty senders: the same size as nobody').toBe(none.encBytes);
  expect(await keys()).toEqual(['held_counts:v1', 'notes_encryption_salt']);
});

test('C7 a thread delete keeps every held note and changes no count', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('TM'));
  await put(page, mkNote('m-ord', 'TM', B));
  await put(page, mkNote('m-h1', 'TM', A, { held: true }));
  await put(page, mkNote('m-h2', 'TM', A, { held: true }));
  expect(await held(page, A)).toEqual({ count: 2 });
  await page.evaluate(() => window.__fz.del('TM'));
  expect(await held(page, A)).toEqual({ count: 2 });
  await expectRowEqualsScan(page, [A, B], 'after deleteThread');
  expect(await page.evaluate(() => window.__fz.get('m-ord'))).toBeNull();
});

test('C8 a write racing a reconcile never loses a count: the row ends up equal to the scan', async ({ page }) => {
  test.setTimeout(180_000);
  await setup(page, 'reconciled');
  await seed(page, { threads: 20, ordinary: 1500, held: 0, heldFrom: A });
  for (let round = 0; round < 2; round++) {
    await page.evaluate(async (r) => {
      const mk = (id: string) => ({ note_id: id, thread_id: 'S-held', direction: 'inbound', from_fingerprint: 'ab'.repeat(32), to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: id, participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true });
      const rec = window.__fz.reconcile();   // a walk over ~1500 notes, started first
      const writes: Promise<unknown>[] = [];
      for (let i = 0; i < 12; i++) writes.push(window.__fz.putNote(mk(`race-${r}-${i}`) as never));
      await Promise.all(writes);
      await rec;
    }, round);
    let result = await page.evaluate(() => window.__fz.reconcile());
    for (let i = 0; i < 3 && result !== 'ok'; i++) result = await page.evaluate(() => window.__fz.reconcile());
    expect(result).toBe('ok');
    expect(await held(page, A)).toEqual({ count: 12 * (round + 1) });
    await expectRowEqualsScan(page, [A], `race round ${round}`);
  }
});

test('C9 the per-arrival check is an order of magnitude cheaper than the scan on a store the size of the launch gate (500 held + 2000 ordinary)', async ({ page }) => {
  test.setTimeout(240_000);
  await setup(page, 'reconciled');
  await seed(page, { threads: 20, ordinary: 2000, held: 500, heldFrom: A });
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect(await held(page, A)).toEqual({ count: 500 });
  const t = await page.evaluate(async (f) => {
    const med = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
    const time = async (fn: () => Promise<unknown>) => { const s = performance.now(); await fn(); return performance.now() - s; };
    const fast: number[] = []; const full: number[] = [];
    for (let i = 0; i < 5; i++) { fast.push(await time(() => window.__fz.fast(f))); full.push(await time(() => window.__fz.countHeld(f))); }
    return { fast: med(fast), full: med(full), answer: await window.__fz.fast(f) };
  }, A);
  console.log(`C9_TIMING ${JSON.stringify(t)}`);
  expect(t.answer).toBe(500);
  expect(t.fast * 10, `fast ${t.fast.toFixed(1)} ms vs scan ${t.full.toFixed(1)} ms`).toBeLessThan(t.full);
});

test('C10 two TABS writing held notes at the same time never lose a count (the per-tab queue does not coordinate tabs: the compare-and-swap does)', async ({ context }) => {
  test.setTimeout(120_000);
  const open = async () => {
    const pg = await context.newPage();
    await pg.goto('/');
    await pg.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
    return pg;
  };
  const p1 = await open();
  expect(await p1.evaluate((o) => window.__fz.initReconciled(o), OWNER)).toBe('ok');
  await putThread(p1, mkThread('TH', true));
  const p2 = await open();
  await p2.evaluate((o) => window.__fz.init(o), OWNER);   // the same owner, so the same database and the same count row
  const burst = (pg: Page, tag: string) => pg.evaluate(async (t) => {
    const mk = (id: string) => ({ note_id: id, thread_id: 'TH', direction: 'inbound', from_fingerprint: 'ab'.repeat(32), to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: id, participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true });
    const results: Array<'ok' | string> = [];
    for (let i = 0; i < 30; i++) {
      try { await window.__fz.putNote(mk(`tab-${t}-${i}`) as never); results.push('ok'); } catch (e) { results.push(String(e)); }
    }
    return results;
  }, tag);
  const [r1, r2] = await Promise.all([burst(p1, 'one'), burst(p2, 'two')]);
  const wrote = [...r1, ...r2].filter((r) => r === 'ok').length;
  // A write that cannot commit THROWS (the accept retries); it never leaves a note without its count. So the row must say exactly the number of notes that were written.
  expect(await held(p1, A)).toEqual({ count: wrote });
  expect(await scan(p1, A)).toBe(wrote);
  expect(wrote, 'and nearly all of them did write').toBeGreaterThanOrEqual(55);
});

/** Base64 length of an AES-GCM ciphertext of `plain` bytes (the tag adds 16): what the stored row's size is for a payload of that length. */
const b64Len = (plain: number): number => 4 * Math.ceil((plain + 16) / 3);

test('C11 the SEALED length is the same for nobody and for the LARGEST count one bucket holds, and one more sender rolls it to exactly the next bucket (the pure rule, proved on the real sealed row)', async ({ page }) => {
  test.setTimeout(180_000);
  await setup(page, 'reconciled');
  const fp = (i: number) => i.toString(16).padStart(64, '0');
  const bytesOf = (k: number): number => JSON.stringify(sealedShape({ state: 'ok', counts: new Map(Array.from({ length: k }, (_, i): [string, number] => [fp(i), 1])) })).length;
  let most = 0;
  while (bytesOf(most + 1) === HELD_COUNTS_BUCKET) most++;
  const row = async () => (await page.evaluate(() => window.__fz.settingsRows())).find((r) => r.key === 'held_counts:v1')!;
  const none = await row();
  expect(none.encBytes, 'the length formula holds for nobody frozen').toBe(b64Len(HELD_COUNTS_BUCKET));
  await putThread(page, mkThread('TH', true));
  await page.evaluate(async (a) => {
    for (let i = 0; i < a.k; i++) await window.__fz.putNote({ note_id: `b-${i}`, thread_id: 'TH', direction: 'inbound', from_fingerprint: i.toString(16).padStart(64, '0'), to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: 'x', participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true } as never);
  }, { k: most });
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect((await row()).encBytes, `${most} senders (the most one bucket holds): the same sealed length as nobody`).toBe(none.encBytes);
  await put(page, mkNote('b-extra', 'TH', fp(most), { held: true }));
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect((await row()).encBytes, 'one more sender: exactly the next bucket').toBe(b64Len(2 * HELD_COUNTS_BUCKET));
});

test('C12 the row EXISTS after the first unlock for a user who never froze anyone, created by the unlock-time reconcile with no write and nobody waiting for it', async ({ page }) => {
  await page.goto('/');
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  await page.evaluate((o) => window.__fz.initOnly(o), OWNER);
  await expect.poll(async () => (await page.evaluate(() => window.__fz.settingsRows())).map((r) => r.key), { timeout: 10_000 }).toEqual(['held_counts:v1', 'notes_encryption_salt']);
  expect(await held(page, A), 'and it says nobody is frozen (a usable row, not "unknown")').toEqual({ count: 0 });
});

test('C13 an ABSENT row while held notes ALREADY EXIST (the store as an older build left it) is never read as "none held": a held write makes it dirty, never a small wrong number', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('TH', true));
  for (let i = 0; i < 3; i++) await put(page, mkNote(`o${i}`, 'TH', A, { held: true }));
  expect(await held(page, A)).toEqual({ count: 3 });
  await page.evaluate(() => window.__fz.deleteSetting('held_counts:v1'));
  expect(await held(page, A)).toEqual({ fallback: 'absent' });
  await put(page, mkNote('o3', 'TH', A, { held: true }));
  const now = await held(page, A);
  expect(now.hasOwnProperty('fallback') || (now as { count: number }).count === 4, 'a fallback, or exactly the truth: never 1').toBeTruthy();
  expect(await page.evaluate((f) => window.__fz.fast(f), A)).toBe(4);
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect(await held(page, A)).toEqual({ count: 4 });
});

test('C14 two TABS delivering the SAME note at the same time: exactly one of them creates it, and it is counted once', async ({ context }) => {
  test.setTimeout(120_000);
  const open = async () => { const pg = await context.newPage(); await pg.goto('/'); await pg.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') }); return pg; };
  const p1 = await open();
  expect(await p1.evaluate((o) => window.__fz.initReconciled(o), OWNER)).toBe('ok');
  await putThread(p1, mkThread('TH', true));
  const p2 = await open();
  await p2.evaluate((o) => window.__fz.init(o), OWNER);
  let created = 0;
  for (let i = 0; i < 10; i++) {
    const n = mkNote(`same-${i}`, 'TH', A, { held: true });
    const res = await Promise.all([put(p1, n), put(p2, n)]) as boolean[];
    expect(res.filter(Boolean).length, `note ${i}: exactly one tab creates it`).toBe(1);
    created += res.filter(Boolean).length;
  }
  expect(created).toBe(10);
  expect(await held(p1, A)).toEqual({ count: 10 });
  expect(await scan(p1, A)).toBe(10);
});

test('C15 a held row that can no longer be READ and is then overwritten makes the count unknown, never a stale number', async ({ page }) => {
  await setup(page, 'reconciled');
  await putThread(page, mkThread('TH', true));
  for (let i = 1; i <= 3; i++) await put(page, mkNote(`u${i}`, 'TH', A, { held: true }));
  expect(await held(page, A)).toEqual({ count: 3 });
  await page.evaluate(() => window.__fz.corruptNote('u1', 'TH'));
  await put(page, mkNote('u1', 'TH', A));   // the unreadable held row is replaced by an ordinary note: the truth is now 2
  const now = await held(page, A);
  expect(now.hasOwnProperty('fallback') || (now as { count: number }).count === 2, 'unknown, or exactly the truth: never the stale 3').toBeTruthy();
  expect(await page.evaluate((f) => window.__fz.fast(f), A)).toBe(2);
  expect(await page.evaluate(() => window.__fz.reconcile())).toBe('ok');
  expect(await held(page, A)).toEqual({ count: 2 });
});

test('C16 a reconcile that read an ABSENT row before its walk cannot overwrite a held note that landed during the walk: the row ends up equal to the scan', async ({ page }) => {
  test.setTimeout(180_000);
  await setup(page, 'reconciled');
  await seed(page, { threads: 20, ordinary: 1500, held: 0, heldFrom: A });
  for (let round = 0; round < 2; round++) {
    await page.evaluate(() => window.__fz.deleteSetting('held_counts:v1'));
    await page.evaluate(async (r) => {
      const mk = (id: string) => ({ note_id: id, thread_id: 'S-held', direction: 'inbound', from_fingerprint: 'ab'.repeat(32), to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: id, participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true });
      const rec = window.__fz.reconcile();   // reads the (absent) row, then walks ~1500 notes
      const writes: Promise<unknown>[] = [];
      for (let i = 0; i < 12; i++) writes.push(window.__fz.putNote(mk(`absent-${r}-${i}`) as never));
      await Promise.all(writes);
      await rec;
    }, round);
    let result = await page.evaluate(() => window.__fz.reconcile());
    for (let i = 0; i < 3 && result !== 'ok'; i++) result = await page.evaluate(() => window.__fz.reconcile());
    expect(result).toBe('ok');
    expect(await held(page, A)).toEqual({ count: 12 * (round + 1) });
    await expectRowEqualsScan(page, [A], `absent-row race round ${round}`);
  }
});

