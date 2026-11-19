import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * Freeze keep, in a REAL browser: the real encrypted notes store (IndexedDB + AES-GCM), nothing stubbed. The unit tests hold the rules (held-note, held-accept) and static
 * pins hold the wiring (held-readers); this proves the REAL store honours them:
 *  - the default readers never return a held note or a held thread; the named include-held readers do;
 *  - a held note never expires on the sender's own retention, an ordinary expired note still does;
 *  - AT REST a held row has exactly the plaintext keys an ordinary row has, and no plaintext `held` anywhere (the flag lives inside the sealed payload);
 *  - the per-sender count sees held notes (also in a held-only thread), only that sender's, case-insensitively;
 *  - deleteThread removes what the owner can see, keeps every held note AND the thread row they hang on (flagged held), and the cap count still reaches them;
 *  - the replay guard reads held sent_at; a redelivered id reports "not created".
 */
const OWNER = 'owner-freeze-store-e2e';
const SENDER = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);

const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

const thread = (id: string, held = false) => ({ thread_id: id, kind: 'direct', participants: [], created_at: '2026-01-01T00:00:00.000Z', last_activity_at: '2026-01-02T00:00:00.000Z', retention: { expires_at: null }, ...(held ? { held: true } : {}) });
const note = (id: string, threadId: string, over: Record<string, unknown> = {}) => ({
  note_id: id, thread_id: threadId, direction: 'inbound', from_fingerprint: SENDER, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: `body of ${id}`,
  participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...over,
});

async function setup(page: Page) {
  await page.goto('/');
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  await page.evaluate((o) => window.__fz.init(o), OWNER);
}
const ids = (rows: Array<{ note_id?: string; thread_id?: string }>) => rows.map((r) => r.note_id ?? r.thread_id).sort();

test('F1 the default readers never return a held note or a held thread; the named include-held readers do', async ({ page }) => {
  await setup(page);
  await page.evaluate(async (args: unknown[]) => { const [t1, t2, n1, n2, n3] = args as never[];
    await window.__fz.putThread(t1 as never); await window.__fz.putThread(t2 as never);
    await window.__fz.putNote(n1 as never); await window.__fz.putNote(n2 as never); await window.__fz.putNote(n3 as never);
  }, [thread('T-mixed'), thread('T-held-only', true), note('n-ord', 'T-mixed'), note('n-held', 'T-mixed', { held: true }), note('n-held2', 'T-held-only', { held: true })]);
  expect(ids(await page.evaluate(() => window.__fz.threads()))).toEqual(['T-mixed']);
  expect(ids(await page.evaluate(() => window.__fz.allThreads()))).toEqual(['T-held-only', 'T-mixed']);
  expect(ids(await page.evaluate(() => window.__fz.notes('T-mixed')))).toEqual(['n-ord']);
  expect(ids(await page.evaluate(() => window.__fz.allNotes('T-mixed')))).toEqual(['n-held', 'n-ord']);
  expect(ids(await page.evaluate(() => window.__fz.notes('T-held-only')))).toEqual([]);
  expect(ids(await page.evaluate(() => window.__fz.allNotes('T-held-only')))).toEqual(['n-held2']);
});

test('F2 a HELD note never expires on the sender\'s own retention; an ordinary expired note still does (and is deleted)', async ({ page }) => {
  await setup(page);
  const past = '2020-01-01T00:00:00.000Z';
  await page.evaluate(async (args: unknown[]) => { const [t, a, b] = args as never[]; await window.__fz.putThread(t as never); await window.__fz.putNote(a as never); await window.__fz.putNote(b as never); },
    [thread('T-ret'), note('n-held-expired', 'T-ret', { held: true, retention: { expires_at: past } }), note('n-ord-expired', 'T-ret', { retention: { expires_at: past } })]);
  expect(ids(await page.evaluate(() => window.__fz.allNotes('T-ret')))).toEqual(['n-held-expired']);
  expect(await page.evaluate(() => window.__fz.get('n-held-expired'))).not.toBeNull();
  expect(await page.evaluate(() => window.__fz.get('n-ord-expired')), 'the ordinary expired note was deleted by the read').toBeNull();
});

test('F3 AT REST a held row has exactly the plaintext keys an ordinary row has, and nothing in plaintext says held', async ({ page }) => {
  await setup(page);
  await page.evaluate(async (args: unknown[]) => { const [t, a, b, th] = args as never[]; await window.__fz.putThread(t as never); await window.__fz.putThread(th as never); await window.__fz.putNote(a as never); await window.__fz.putNote(b as never); },
    [thread('T-r1'), note('n-r1', 'T-r1'), note('n-r2', 'T-r1', { held: true }), thread('T-r2', true)]);
  const rows = await page.evaluate(() => window.__fz.raw());
  const noteRows = rows.filter((r) => r.store === 'notes'), threadRows = rows.filter((r) => r.store === 'threads');
  expect(noteRows.length).toBe(2); expect(threadRows.length).toBe(2);
  expect(new Set(noteRows.map((r) => r.keys.join(','))).size, 'both note rows have the same key set').toBe(1);
  expect(new Set(noteRows.map((r) => r.encKeys.join(','))).size, 'and the same blob fields').toBe(1);
  expect(new Set(threadRows.map((r) => r.keys.join(','))).size, 'both thread rows have the same key set').toBe(1);
  // the test ids above are deliberately neutral: the only plaintext in a row is its ids, so a match here could only come from the store itself
  expect(JSON.stringify(rows.map((r) => r.plaintext)), 'no plaintext column or value mentions held').not.toMatch(/held/i);
  expect(JSON.stringify(rows.map((r) => r.keys)), 'no key name mentions held').not.toMatch(/held/i);
});

test('F4 the per-sender count sees held notes (also in a held-only thread), only THAT sender\'s, ignoring case; ordinary notes are not counted', async ({ page }) => {
  await setup(page);
  await page.evaluate(async (rows: unknown[]) => { for (const r of rows as Array<{ kind: string; v: never }>) { if (r.kind === 't') await window.__fz.putThread(r.v); else await window.__fz.putNote(r.v); } },
    [
      { kind: 't', v: thread('T-a') }, { kind: 't', v: thread('T-b', true) },
      { kind: 'n', v: note('c1', 'T-a', { held: true }) }, { kind: 'n', v: note('c2', 'T-b', { held: true }) },
      { kind: 'n', v: note('c3', 'T-a') },                                                   // ordinary: not counted
      { kind: 'n', v: note('c4', 'T-a', { held: true, from_fingerprint: OTHER }) },           // another sender's held: not counted
      { kind: 'n', v: note('c5', 'T-b', { held: true, from_fingerprint: SENDER.toUpperCase() }) }, // same sender, different case: counted
    ]);
  expect(await page.evaluate((f) => window.__fz.countHeld(f), SENDER)).toBe(3);
  expect(await page.evaluate((f) => window.__fz.countHeld(f), OTHER)).toBe(1);
  expect(await page.evaluate((f) => window.__fz.countHeld(f), 'ef'.repeat(32))).toBe(0);
});

test('F5 deleteThread removes what the owner can see, KEEPS every held note and the thread row they hang on (flagged held); the cap count still reaches them', async ({ page }) => {
  await setup(page);
  await page.evaluate(async (args: unknown[]) => { const [t, a, b, c, th2, d] = args as never[]; await window.__fz.putThread(t as never); await window.__fz.putNote(a as never); await window.__fz.putNote(b as never); await window.__fz.putNote(c as never);
    await window.__fz.putThread(th2 as never); await window.__fz.putNote(d as never); },
    [thread('T-del'), note('d-ord', 'T-del'), note('d-held1', 'T-del', { held: true }), note('d-held2', 'T-del', { held: true }), thread('T-del-plain'), note('d-plain', 'T-del-plain')]);
  await page.evaluate(() => window.__fz.del('T-del'));
  expect(ids(await page.evaluate(() => window.__fz.allNotes('T-del'))), 'the ordinary note is gone, both held notes remain').toEqual(['d-held1', 'd-held2']);
  expect(ids(await page.evaluate(() => window.__fz.notes('T-del'))), 'and the owner sees nothing').toEqual([]);
  const allT = await page.evaluate(() => window.__fz.allThreads());
  expect(allT.find((t) => t.thread_id === 'T-del')?.held, 'the thread row they hang on was kept and flagged held').toBe(true);
  expect(ids(await page.evaluate(() => window.__fz.threads())), 'a held thread is hidden from the default reader').not.toContain('T-del');
  expect(await page.evaluate((f) => window.__fz.countHeld(f), SENDER), 'the cap count still reaches the held notes of the deleted conversation').toBe(2);
  // control: a thread with NO held notes is deleted whole, row included
  await page.evaluate(() => window.__fz.del('T-del-plain'));
  expect(ids(await page.evaluate(() => window.__fz.allThreads()))).not.toContain('T-del-plain');
  expect(await page.evaluate(() => window.__fz.get('d-plain'))).toBeNull();
});

test('F6 the replay guard reads HELD notes\' sent_at; a redelivered id reports "not created" (held or not)', async ({ page }) => {
  await setup(page);
  await page.evaluate(async (args: unknown[]) => { const [t, a, b] = args as never[]; await window.__fz.putThread(t as never); await window.__fz.putNote(a as never); await window.__fz.putNote(b as never); },
    [thread('T-replay'), note('r-ord', 'T-replay', { sent_at: '2026-02-01T00:00:00.000Z' }), note('r-held', 'T-replay', { held: true, sent_at: '2026-03-01T00:00:00.000Z' })]);
  expect((await page.evaluate((f) => window.__fz.sentAt(f), SENDER)).sort()).toEqual(['2026-02-01T00:00:00.000Z', '2026-03-01T00:00:00.000Z']);
  const again = await page.evaluate((n) => window.__fz.putNote(n as never), note('r-held', 'T-replay', { held: true, sent_at: '2026-03-01T00:00:00.000Z' }) as never);
  expect(again, 'the same id again is not a creation').toBe(false);
});
