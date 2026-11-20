import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * The owner's two actions on a held note, in a REAL browser against the real encrypted notes store (IndexedDB + AES-GCM), nothing stubbed. The unit tests hold the rules (held-release.test.ts) and static pins hold
 * the wiring (held-age-wiring.test.ts, held-counts-wiring.test.ts); this proves the REAL store does what the hold view needs:
 *  - a RELEASE makes an ordinary note (held, held_at and expiry_seen_at all gone), drops the count, and un-holds the thread, in ONE commit: the thread's last_activity_at does not move, and another held note in
 *    the same thread stays hidden;
 *  - a DELETE is counted (the row equals the full scan after it) and leaves the thread row in place, so a held note is never stranded;
 *  - neither can touch a note that is not held, a note that is gone, or one that cannot be read;
 *  - one sender's held notes come back newest first, case-insensitively, and the senders list counts them;
 *  - and two tabs, one releasing and deleting while the other writes new held notes, never lose a count.
 */
const OWNER = 'owner-hold-view-store-e2e';
const A = 'ab'.repeat(32);
const B = 'cd'.repeat(32);
const DAY = 86_400_000;
const NOW = Date.parse('2026-06-01T12:00:00.000Z');
const iso = (ms: number): string => new Date(ms).toISOString();

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function setup(page: Page) {
  await page.goto('/');
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  expect(await page.evaluate((o) => window.__fz.initReconciled(o), OWNER)).toBe('ok');
}

const mkThread = (id: string, held = false) => ({ thread_id: id, kind: 'direct', participants: [], created_at: '2026-01-01T00:00:00.000Z', last_activity_at: '2026-01-02T00:00:00.000Z', retention: { expires_at: null }, ...(held ? { held: true } : {}) });
const mkNote = (id: string, threadId: string, from: string, over: Record<string, unknown> = {}) => ({
  note_id: id, thread_id: threadId, direction: 'inbound', from_fingerprint: from, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: `body of ${id}`,
  participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...over,
});
const heldNote = (id: string, threadId: string, over: Record<string, unknown> = {}) => mkNote(id, threadId, A, { held: true, held_at: iso(NOW), ...over });
const put = (page: Page, n: unknown) => page.evaluate((x) => window.__fz.putNote(x as never), n);
const putThread = (page: Page, t: unknown) => page.evaluate((x) => window.__fz.putThread(x as never), t);
const get = (page: Page, id: string) => page.evaluate((x) => window.__fz.get(x), id) as Promise<Record<string, unknown> | null>;
const release = (page: Page, id: string) => page.evaluate((x) => window.__fz.releaseHeld(x), id);
const remove = (page: Page, id: string) => page.evaluate((x) => window.__fz.deleteHeld(x), id);
const held = (page: Page, fp: string) => page.evaluate((f) => window.__fz.held(f), fp);
const scan = (page: Page, fp: string) => page.evaluate((f) => window.__fz.countHeld(f), fp);
const visibleThreads = (page: Page) => page.evaluate(() => window.__fz.threads().then((r) => r.map((t) => t.thread_id).sort()));
const allThreads = (page: Page) => page.evaluate(() => window.__fz.allThreads().then((r) => r.map((t) => ({ id: t.thread_id, held: (t as { held?: boolean }).held === true, last: t.last_activity_at })).sort((a, b) => (a.id < b.id ? -1 : 1))));
const visibleNotes = (page: Page, t: string) => page.evaluate((x) => window.__fz.notes(x).then((r) => r.map((n) => n.note_id).sort()), t);
const allNoteIds = (page: Page, t: string) => page.evaluate((x) => window.__fz.allNotes(x).then((r) => r.map((n) => n.note_id).sort()), t);
async function expectRowEqualsScan(page: Page, who: string[], why: string) {
  for (const fp of who) expect({ why, fp: fp.slice(0, 4), row: await held(page, fp) }).toEqual({ why, fp: fp.slice(0, 4), row: { count: await scan(page, fp) } });
}

test('HS1 releasing ONE of two held notes in a thread: it becomes an ordinary note with none of the three keys, the thread is un-held WITHOUT moving last_activity_at, the other note stays hidden, and the count follows', async ({ page }) => {
  await setup(page);
  await putThread(page, mkThread('T', true));
  await put(page, heldNote('n1', 'T', { expiry_seen_at: iso(NOW - DAY) }));
  await put(page, heldNote('n2', 'T'));
  expect(await visibleThreads(page)).toEqual([]);
  const lastBefore = (await allThreads(page))[0].last;
  expect(await held(page, A)).toEqual({ count: 2 });

  expect(await release(page, 'n1')).toBe('done');
  const n1 = (await get(page, 'n1')) as Record<string, unknown>;
  for (const k of ['held', 'held_at', 'expiry_seen_at']) expect(k in n1, `no ${k} on the released note`).toBe(false);
  expect(n1.body).toBe('body of n1');
  expect(await visibleThreads(page), 'the thread is now an ordinary thread').toEqual(['T']);
  expect((await allThreads(page))[0].last, 'last_activity_at did NOT move').toBe(lastBefore);
  expect(await visibleNotes(page, 'T'), 'only the released note shows: the other held note stays hidden').toEqual(['n1']);
  expect(await allNoteIds(page, 'T')).toEqual(['n1', 'n2']);
  expect(await held(page, A)).toEqual({ count: 1 });
  await expectRowEqualsScan(page, [A], 'after releasing one of two');
  expect(await release(page, 'n1'), 'a second release of the same note: it is not held any more').toBe('not-held');
});

test('HS2 releasing the LAST held note of a thread: the note shows in an ordinary thread, the count is 0, the row equals the scan', async ({ page }) => {
  await setup(page);
  await putThread(page, mkThread('T', true));
  await put(page, heldNote('n1', 'T'));
  expect(await release(page, 'n1')).toBe('done');
  expect(await visibleThreads(page)).toEqual(['T']);
  expect(await visibleNotes(page, 'T')).toEqual(['n1']);
  expect(await held(page, A)).toEqual({ count: 0 });
  await expectRowEqualsScan(page, [A], 'after releasing the last');
});

test('HS3 DELETE is counted and leaves the thread row in place: the row equals the scan after each delete, and the (empty) held thread stays hidden so nothing is stranded', async ({ page }) => {
  await setup(page);
  await putThread(page, mkThread('T', true));
  for (const id of ['n1', 'n2', 'n3']) await put(page, heldNote(id, 'T'));
  expect(await remove(page, 'n2')).toBe('done');
  expect(await held(page, A)).toEqual({ count: 2 });
  await expectRowEqualsScan(page, [A], 'after one delete');
  expect(await remove(page, 'n2'), 'a second delete of the same note').toBe('gone');
  expect(await remove(page, 'n1')).toBe('done');
  expect(await remove(page, 'n3')).toBe('done');
  expect(await held(page, A)).toEqual({ count: 0 });
  await expectRowEqualsScan(page, [A], 'after deleting every note');
  expect((await allThreads(page)).map((t) => ({ id: t.id, held: t.held })), 'the empty held thread row is still there, still held').toEqual([{ id: 'T', held: true }]);
  expect(await visibleThreads(page), 'and still hidden from every ordinary reader').toEqual([]);
});

test('HS4 a new held note landing on the thread AFTER its last note was deleted is found (held notes are found by walking threads, and the thread row is still there)', async ({ page }) => {
  await setup(page);
  await putThread(page, mkThread('T', true));
  await put(page, heldNote('n1', 'T'));
  expect(await remove(page, 'n1')).toBe('done');
  await put(page, heldNote('n2', 'T'));
  expect((await page.evaluate((f) => window.__fz.heldFrom(f), A)).map((n) => n.note_id)).toEqual(['n2']);
  expect(await held(page, A)).toEqual({ count: 1 });
  await expectRowEqualsScan(page, [A], 'after the landing');
});

test('HS5 neither action touches a note that is not held, a note that is gone, or one that cannot be read; and a release with no thread row leaves the note held', async ({ page }) => {
  await setup(page);
  await putThread(page, mkThread('T'));
  await putThread(page, mkThread('H', true));
  await put(page, mkNote('ord', 'T', A, { held_at: iso(NOW - 90 * DAY), expiry_seen_at: iso(NOW - 60 * DAY) }));   // ordinary, carrying look-alike stamps
  const before = JSON.stringify(await get(page, 'ord'));
  expect(await remove(page, 'ord'), 'delete refuses an ordinary note').toBe('not-held');
  expect(await release(page, 'ord'), 'release refuses an ordinary note').toBe('not-held');
  expect(JSON.stringify(await get(page, 'ord')), 'and it is byte-for-byte what it was').toBe(before);
  expect(await remove(page, 'nope')).toBe('gone');
  expect(await release(page, 'nope')).toBe('gone');
  await put(page, heldNote('bad', 'H'));
  await page.evaluate(() => window.__fz.corruptNote('bad', 'H'));
  expect(await remove(page, 'bad')).toBe('unreadable');
  expect(await release(page, 'bad')).toBe('unreadable');
  const raw = await page.evaluate(() => window.__fz.raw());
  expect(raw.filter((r) => r.store === 'notes').map((r) => r.plaintext.note_id).sort(), 'the unreadable row is still at rest').toEqual(['bad', 'ord']);
  // a held note whose thread row is missing: the release would leave an ordinary note no thread lists, so it is refused
  await put(page, heldNote('orphan', 'NO-SUCH-THREAD'));
  const countBefore = await held(page, A);
  expect(await release(page, 'orphan')).toBe('unreadable');
  expect((await get(page, 'orphan'))?.held, 'it is still held').toBe(true);
  expect(await held(page, A)).toEqual(countBefore);
  // a held note whose thread row cannot be read: the release cannot know whether the thread is held, so it is refused and nothing changes (the delete does not need the thread and still works)
  await putThread(page, mkThread('TB', true));
  await put(page, heldNote('tbad', 'TB'));
  await page.evaluate(() => window.__fz.corruptThread('TB'));
  const countBeforeTb = await held(page, A);
  expect(await release(page, 'tbad'), 'a release with an unreadable thread is refused').toBe('unreadable');
  expect((await get(page, 'tbad'))?.held, 'the note is still held').toBe(true);
  expect(await held(page, A), 'and the count did not move').toEqual(countBeforeTb);
  expect(await remove(page, 'tbad'), 'a delete does not read the thread').toBe('done');
});

test('HS6 one sender\'s held notes come back NEWEST FIRST by when they were held, case-insensitively, and only that sender\'s; the senders list counts them', async ({ page }) => {
  await setup(page);
  await putThread(page, mkThread('T', true));
  await put(page, heldNote('old', 'T', { held_at: iso(NOW - 5 * DAY) }));
  await put(page, heldNote('new', 'T', { held_at: iso(NOW - DAY) }));
  await put(page, heldNote('mid', 'T', { held_at: iso(NOW - 3 * DAY) }));
  await put(page, mkNote('other', 'T', B, { held: true, held_at: iso(NOW) }));
  await put(page, mkNote('outbound', 'T', A, { direction: 'outbound', held: true, held_at: iso(NOW) }));
  expect((await page.evaluate((f) => window.__fz.heldFrom(f), A)).map((n) => n.note_id)).toEqual(['new', 'mid', 'old']);
  expect((await page.evaluate((f) => window.__fz.heldFrom(f), A.toUpperCase())).map((n) => n.note_id), 'upper-case asks the same').toEqual(['new', 'mid', 'old']);
  expect(await page.evaluate(() => window.__fz.heldSenders())).toEqual([{ from_fingerprint: A, count: 3 }, { from_fingerprint: B, count: 1 }]);
});

test('HS7 TWO TABS: one releasing and deleting held notes while the other writes new ones never loses a count (the per-tab queue does not coordinate tabs: the compare-and-swap does)', async ({ context }) => {
  test.setTimeout(180_000);
  const open = async () => {
    const pg = await context.newPage();
    await pg.goto('/');
    await pg.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
    return pg;
  };
  const p1 = await open();
  expect(await p1.evaluate((o) => window.__fz.initReconciled(o), OWNER)).toBe('ok');
  await putThread(p1, mkThread('T', true));
  const p2 = await open();
  await p2.evaluate((o) => window.__fz.init(o), OWNER);
  for (let i = 0; i < 60; i++) await put(p1, heldNote(`old-${i}`, 'T'));
  expect(await held(p1, A)).toEqual({ count: 60 });
  const burst = (pg: Page) => pg.evaluate(async (a) => {
    const mk = (id: string) => ({ note_id: id, thread_id: 'T', direction: 'inbound', from_fingerprint: a, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: id, participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true, held_at: new Date().toISOString() });
    const results: string[] = [];
    for (let i = 0; i < 30; i++) {
      try { await window.__fz.putNote(mk(`new-${i}`) as never); results.push('ok'); } catch (e) { results.push(String(e)); }
    }
    return results;
  }, A);
  const work = p1.evaluate(async () => {
    const out: string[] = [];
    for (let i = 0; i < 60; i++) out.push(i % 2 === 0 ? await window.__fz.releaseHeld(`old-${i}`) : await window.__fz.deleteHeld(`old-${i}`));
    return out;
  });
  const [res, wrote] = await Promise.all([work, burst(p2)]);
  const written = wrote.filter((r) => r === 'ok').length;
  const done = res.filter((r) => r === 'done').length;
  expect(res.every((r) => r === 'done' || r === 'lost-race'), `each answer is done or an honest lost-race: ${[...new Set(res)].join(',')}`).toBe(true);
  expect(done, 'and most of them went through').toBeGreaterThanOrEqual(40);
  await expectRowEqualsScan(p1, [A], 'two tabs: owner moves and deletes while new notes land');
  expect(await scan(p1, A)).toBe(written + (60 - done));
  expect(written, 'and nearly all the writes landed').toBeGreaterThanOrEqual(20);
});
