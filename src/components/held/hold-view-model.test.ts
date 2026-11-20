// Run: npx tsx --test src/components/held/hold-view-model.test.ts
// What the hold view does that is not drawing: the two loops over ALL notes (stop at the first failure, count only what was done, RE-COUNT what is still held, never infer it), the lines under each note, and
// the rule that Delete never reaches a note that is not held. Run against a fake port; the real store is run in a real browser by e2e/hold-view.spec.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { HeldMoveResult } from '@/lib/messaging/held-note';
import type { NoteRecord } from '@/lib/messaging/types';
import { deleteAllHeld, moveAllHeld, noteLines, senderTag, type HeldPort } from './hold-view-model';

const DAY = 86_400_000;
const NOW = Date.parse('2026-06-01T12:00:00.000Z');
const iso = (ms: number): string => new Date(ms).toISOString();
const note = (id: string, over: Partial<NoteRecord> = {}): NoteRecord => ({
  note_id: id, thread_id: 'thr', direction: 'inbound', from_fingerprint: 'ab'.repeat(32), to_fingerprints: [], sent_at: iso(NOW - 3 * DAY), body: `body ${id}`,
  participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true, ...over,
} as NoteRecord);

/** A fake port: `answers` gives each note id's answer (default 'done'); `held` is what the store would list when asked AGAIN (the re-count). */
function fakePort(answers: Record<string, HeldMoveResult | 'throw'> = {}, held: NoteRecord[] = []) {
  const calls = { release: [] as string[], remove: [] as string[], list: 0 };
  const run = (id: string): HeldMoveResult => {
    const a = answers[id] ?? 'done';
    if (a === 'throw') throw new Error('store locked');
    return a;
  };
  const port: HeldPort = {
    listHeld: async () => { calls.list++; return held; },
    release: async (id) => { calls.release.push(id); return run(id); },
    remove: async (id) => { calls.remove.push(id); return run(id); },
    nowMs: () => NOW,
  };
  return { port, calls };
}
const FP = 'ab'.repeat(32);

test('HM1 moving or deleting ALL: every note done -> ok with the count it did, in order, one at a time, and no re-count is needed', async () => {
  const { port, calls } = fakePort();
  assert.deepEqual(await moveAllHeld(port, FP, ['a', 'b', 'c']), { ok: true, n: 3 });
  assert.deepEqual(calls.release, ['a', 'b', 'c']);
  assert.equal(calls.list, 0, 'nothing failed, so nothing is re-counted');
  const d = fakePort();
  assert.deepEqual(await deleteAllHeld(d.port, FP, ['x', 'y']), { ok: true, n: 2 });
  assert.deepEqual(d.calls.remove, ['x', 'y']);
});

test('HM2 move-all never calls Delete and delete-all never calls Move (each loop reaches only its own operation)', async () => {
  const m = fakePort();
  await moveAllHeld(m.port, FP, ['a', 'b']);
  assert.deepEqual(m.calls.remove, []);
  const d = fakePort();
  await deleteAllHeld(d.port, FP, ['a', 'b']);
  assert.deepEqual(d.calls.release, []);
});

test('HM3 a loop STOPS at the first note it could not handle, and the number still here is RE-COUNTED from the store (here 7), not inferred (a guess from the loop would say 3)', async () => {
  const still = Array.from({ length: 7 }, (_, i) => note(`s${i}`));
  const { port, calls } = fakePort({ c: 'lost-race' }, still);
  const r = await moveAllHeld(port, FP, ['a', 'b', 'c', 'd', 'e']);
  assert.deepEqual(r, { ok: false, stillHere: 7 });
  assert.deepEqual(calls.release, ['a', 'b', 'c'], 'it stopped at c: d and e were not tried');
  assert.equal(calls.list, 1, 'the re-count is ONE read after the failure');
  const u = fakePort({ b: 'unreadable' }, still.slice(0, 2));
  assert.deepEqual(await deleteAllHeld(u.port, FP, ['a', 'b', 'c']), { ok: false, stillHere: 2 });
});

test('HM4 a note a sweep already deleted ("gone") or that already left the hold ("not-held") is NOT a failure and is NOT counted: the loop goes on', async () => {
  const { port } = fakePort({ b: 'gone', c: 'not-held' });
  assert.deepEqual(await moveAllHeld(port, FP, ['a', 'b', 'c', 'd']), { ok: true, n: 2 });
  const d = fakePort({ a: 'not-held' });
  assert.deepEqual(await deleteAllHeld(d.port, FP, ['a', 'b']), { ok: true, n: 1 }, 'an ordinary note (not held) is left alone and not counted as deleted');
});

test('HM5 a port that THROWS (a locked store) is a failure like any other, and a re-count that also throws is the CALLER\'s error: no made-up number', async () => {
  const { port } = fakePort({ a: 'throw' }, [note('s0')]);
  assert.deepEqual(await moveAllHeld(port, FP, ['a', 'b']), { ok: false, stillHere: 1 });
  const broken: HeldPort = { listHeld: async () => { throw new Error('unreadable'); }, release: async () => 'lost-race', remove: async () => 'lost-race', nowMs: () => NOW };
  await assert.rejects(() => moveAllHeld(broken, FP, ['a']), /unreadable/);
});

test('HM6 an empty list is a success of zero (the buttons are not offered then, but the loop must not fail)', async () => {
  const { port, calls } = fakePort();
  assert.deepEqual(await moveAllHeld(port, FP, []), { ok: true, n: 0 });
  assert.deepEqual(calls.release, []);
});

test('HM7 the lines under a note: when it arrived HERE, the sender\'s time labelled as THEIRS, and "expiring" only for a note the SWEEP has marked', () => {
  const plain = noteLines(note('p', { held_at: iso(NOW - DAY) }), NOW);
  assert.match(plain.arrived ?? '', /^Arrived here .+/);
  assert.match(plain.theirs ?? '', /^Sent .+, by their clock$/);
  assert.equal(plain.expiring, null, 'not marked: nothing said');
  const marked = noteLines(note('m', { held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW - 2 * DAY) }), NOW);
  assert.match(marked.expiring ?? '', /^Expiring\. Can be removed after .+\.$/);
  const none = noteLines(note('n', { held_at: undefined, sent_at: 'not a date' }), NOW);
  assert.deepEqual(none, { arrived: null, theirs: null, expiring: null }, 'nothing true to say: nothing said');
});

test('HM8 senderTag is the first eight hex digits, lower-cased: an identifier, not a count', () => {
  assert.equal(senderTag('AB12CD34EF56' + '0'.repeat(52)), 'ab12cd34');
  assert.doesNotMatch(senderTag('ab'.repeat(32)), /\{|\}/);
});
