// What a device holds for one friend's epoch secrets: the acceptance rule, the prev window, the stored shape.
// Refusals and drops first. Run: npx tsx --test src/lib/trust/psi-epoch-book.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  applyEpochNote,
  expirePrev,
  epochElementsFor,
  serializeEpochRecord,
  restoreEpochRecord,
  PSI_PREV_TICKS,
  PSI_EPOCH_RECORD_V,
  type PsiEpochRecord,
  type OpenedNote,
} from './psi-epoch-book';
import { psiElement } from './psi-epoch-element';

const FP = createHash('sha256').update('friend').digest('hex');
const b = (seed: number) => Uint8Array.from({ length: 32 }, (_, i) => (seed + i) % 256);
const note = (epoch: number, k = 1, t = 2): OpenedNote => ({ epoch, know: b(k), trust: b(t) });
const hex = (u: Uint8Array) => bytesToHex(u);
const adopt = (rec: PsiEpochRecord | null, n: OpenedNote, tick: number) => {
  const r = applyEpochNote(rec, n, tick);
  assert.equal(r.outcome, 'adopted');
  return r.record as PsiEpochRecord;
};
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

// ── notes that are not taken in ─────────────────────────────────────────────────────────────────────────────

test('a lower epoch is stale: dropped whole, the record untouched (no rollback)', () => {
  const rec = adopt(null, note(10), 5);
  const before = clone(rec);
  const r = applyEpochNote(rec, note(9, 7, 8), 6);
  assert.equal(r.outcome, 'stale');
  assert.equal(r.record, rec);
  assert.deepEqual(rec, before);
});

test('an equal epoch with the same bytes is a duplicate and the record is returned as is', () => {
  const rec = adopt(null, note(10), 5);
  const r = applyEpochNote(rec, note(10), 99);
  assert.equal(r.outcome, 'duplicate');
  assert.equal(r.record, rec);
  assert.equal(rec.adoptedTick, 5, 'a redelivery must not move the adoption tick (it would extend the prev window)');
});

test('applying the SAME note twice is idempotent: first adopted, then duplicate, and the stored form is byte-identical', () => {
  const n = note(10, 1, 2);
  const first = applyEpochNote(null, n, 5);
  assert.equal(first.outcome, 'adopted');
  const again = applyEpochNote(first.record, n, 9);
  assert.equal(again.outcome, 'duplicate');
  assert.equal(serializeEpochRecord(again.record as PsiEpochRecord), serializeEpochRecord(first.record as PsiEpochRecord));
  // and after a later epoch, redelivering the OLD note is stale, not a second adoption
  const later = applyEpochNote(again.record, note(11, 3, 4), 12);
  assert.equal(later.outcome, 'adopted');
  const replay = applyEpochNote(later.record, n, 13);
  assert.equal(replay.outcome, 'stale');
  assert.equal(serializeEpochRecord(replay.record as PsiEpochRecord), serializeEpochRecord(later.record as PsiEpochRecord));
});

test('an equal epoch with DIFFERENT bytes is a conflict and replaces nothing, in either field', () => {
  const rec = adopt(null, note(10, 1, 2), 5);
  for (const n of [note(10, 9, 2), note(10, 1, 9), note(10, 9, 8)]) {
    const r = applyEpochNote(rec, n, 6);
    assert.equal(r.outcome, 'conflict');
    assert.equal(r.record, rec);
  }
});

test('malformed notes are invalid: identical fields, wrong widths, bad epochs, not bytes', () => {
  const rec = adopt(null, note(10), 5);
  const bad: OpenedNote[] = [
    { epoch: 11, know: b(3), trust: b(3) },
    { epoch: 11, know: new Uint8Array(31), trust: b(3) },
    { epoch: 11, know: b(3), trust: new Uint8Array(33) },
    { epoch: -1, know: b(3), trust: b(4) },
    { epoch: 1.5, know: b(3), trust: b(4) },
    { epoch: Number.MAX_SAFE_INTEGER + 1, know: b(3), trust: b(4) },
    { epoch: NaN, know: b(3), trust: b(4) },
    { epoch: 11, know: 'x' as unknown as Uint8Array, trust: b(4) },
  ];
  for (const n of bad) {
    assert.equal(applyEpochNote(null, n, 0).outcome, 'invalid');
    const r = applyEpochNote(rec, n, 6);
    assert.equal(r.outcome, 'invalid');
    assert.equal(r.record, rec);
  }
});

test('a tick that is not a non-negative safe integer is a programming error', () => {
  for (const t of [-1, 0.5, NaN, Infinity, '3' as unknown as number]) {
    assert.throws(() => applyEpochNote(null, note(1), t), TypeError);
    assert.throws(() => expirePrev(adopt(null, note(1), 0), t), TypeError);
  }
});

// ── notes that are ──────────────────────────────────────────────────────────────────────────────────────────

test('the first note for a friend is adopted at any epoch, including 0, with no prev', () => {
  for (const e of [0, 1, 2 ** 40 + 7]) {
    const rec = adopt(null, note(e), 3);
    assert.equal(rec.cur.e, e);
    assert.equal(rec.prev, null);
    assert.equal(rec.adoptedTick, 3);
    assert.equal(rec.v, PSI_EPOCH_RECORD_V);
  }
});

test('a higher epoch is adopted: cur becomes prev, only ONE generation is kept, and a skipped epoch (e+2) is fine', () => {
  let rec = adopt(null, note(10, 1, 2), 5);
  rec = adopt(rec, note(11, 3, 4), 7);
  assert.equal(rec.cur.e, 11);
  assert.equal(rec.prev?.e, 10);
  assert.equal(rec.prev?.know, hex(b(1)));
  assert.equal(rec.adoptedTick, 7);
  rec = adopt(rec, note(13, 5, 6), 9); // a roll was missed
  assert.equal(rec.cur.e, 13);
  assert.equal(rec.prev?.e, 11, 'the epoch before that (10) is forgotten');
  assert.equal(rec.prev?.know, hex(b(3)));
});

test('applying a note never mutates its inputs', () => {
  const rec = adopt(null, note(10), 5);
  const n = note(11, 3, 4);
  const recBefore = clone(rec);
  const nBefore = { epoch: n.epoch, know: hex(n.know), trust: hex(n.trust) };
  applyEpochNote(rec, n, 6);
  assert.deepEqual(rec, recBefore);
  assert.deepEqual({ epoch: n.epoch, know: hex(n.know), trust: hex(n.trust) }, nBefore);
});

test('a record from a real know field and a decoy trust field has the same shape as one with two real fields', () => {
  const real = adopt(null, note(10, 1, 2), 5);
  const withDecoy = adopt(null, note(10, 1, 77), 5);
  const shape = (r: PsiEpochRecord) => JSON.stringify(clone(r), (_k, v) => (typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) ? 'H64' : v));
  assert.equal(shape(real), shape(withDecoy));
  assert.equal(serializeEpochRecord(real).length, serializeEpochRecord(withDecoy).length);
});

// ── prev window ─────────────────────────────────────────────────────────────────────────────────────────────

test('prev is dropped exactly when PSI_PREV_TICKS of the holder\'s own ticks have passed', () => {
  const rec = adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 100);
  assert.equal(PSI_PREV_TICKS, 12);
  assert.notEqual(expirePrev(rec, 100 + PSI_PREV_TICKS - 1).prev, null, 'one tick before the window ends');
  assert.equal(expirePrev(rec, 100 + PSI_PREV_TICKS).prev, null, 'exactly at the window');
  assert.equal(expirePrev(rec, 100 + 1000).prev, null);
});

test('a tick that went BACKWARDS drops prev (losing a match is the safe direction)', () => {
  const rec = adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 100);
  assert.equal(expirePrev(rec, 99).prev, null);
  assert.equal(expirePrev(rec, 0).prev, null);
});

test('expiring prev keeps cur, does not mutate the input, and returns the same record when there is nothing to drop', () => {
  const rec = adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 100);
  const before = clone(rec);
  const out = expirePrev(rec, 200);
  assert.deepEqual(rec, before);
  assert.deepEqual(out.cur, rec.cur);
  assert.equal(out.adoptedTick, rec.adoptedTick);
  const noPrev = adopt(null, note(1), 0);
  assert.equal(expirePrev(noPrev, 500), noPrev);
  assert.equal(expirePrev(rec, 101), rec);
});

test('a duplicate delivery does not extend the prev window', () => {
  let rec = adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 100);
  rec = applyEpochNote(rec, note(11, 3, 4), 111).record as PsiEpochRecord;
  assert.equal(expirePrev(rec, 112).prev, null);
});

// ── elements ────────────────────────────────────────────────────────────────────────────────────────────────

test('epochElementsFor returns cur then prev, each from the right layer secret and epoch', () => {
  const rec = adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 6);
  const know = epochElementsFor(rec, FP, 'know');
  const trust = epochElementsFor(rec, FP, 'trust');
  assert.deepEqual(know.map((x) => [x.epoch, x.role]), [[11, 'cur'], [10, 'prev']]);
  assert.equal(hex(know[0].element), hex(psiElement(FP, 'know', 11, b(3))));
  assert.equal(hex(know[1].element), hex(psiElement(FP, 'know', 10, b(1))));
  assert.equal(hex(trust[0].element), hex(psiElement(FP, 'trust', 11, b(4))));
  assert.equal(hex(trust[1].element), hex(psiElement(FP, 'trust', 10, b(2))));
  assert.notEqual(hex(know[0].element), hex(trust[0].element));
});

test('epochElementsFor with no prev returns one element, and an expired prev stops producing one', () => {
  const rec = adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 6);
  assert.equal(epochElementsFor(expirePrev(rec, 6 + PSI_PREV_TICKS), FP, 'know').length, 1);
  assert.equal(epochElementsFor(adopt(null, note(1), 0), FP, 'trust').length, 1);
});

test('epochElementsFor refuses a non-canonical friend fingerprint (the element library does)', () => {
  const rec = adopt(null, note(1), 0);
  assert.throws(() => epochElementsFor(rec, FP.toUpperCase(), 'know'));
});

// ── stored shape ────────────────────────────────────────────────────────────────────────────────────────────

test('a record round-trips through its stored form, with and without prev, into a fresh object', () => {
  const one = adopt(null, note(10, 1, 2), 5);
  const two = adopt(one, note(11, 3, 4), 6);
  for (const rec of [one, two]) {
    const back = restoreEpochRecord(serializeEpochRecord(rec));
    assert.deepEqual(back, rec);
    assert.notEqual(back, rec);
  }
});

test('the stored form is pinned (fixed key order), so it cannot drift silently', () => {
  const rec = adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 6);
  assert.equal(
    serializeEpochRecord(rec),
    '{"v":1,"cur":{"e":11,"know":"030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122","trust":"0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"},' +
      '"prev":{"e":10,"know":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","trust":"02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"},"adoptedTick":6}',
  );
});

test('restore refuses every malformed stored form (fail closed)', () => {
  const good = clone(adopt(adopt(null, note(10, 1, 2), 5), note(11, 3, 4), 6));
  const H = (s: number) => hex(b(s));
  type Loose = Record<string, unknown>;
  const sub = (r: Loose, k: string) => r[k] as Loose;
  const mutate = (f: (r: Loose) => void) => {
    const r = clone(good) as unknown as Loose;
    f(r);
    return JSON.stringify(r);
  };
  const bad: Array<[string, unknown]> = [
    ['not a string', 42],
    ['null', null],
    ['undefined', undefined],
    ['empty string', ''],
    ['not JSON', '{nope'],
    ['an array', '[]'],
    ['JSON null', 'null'],
    ['wrong version', mutate((r) => { r.v = 2; })],
    ['version as a string', mutate((r) => { r.v = '1'; })],
    ['missing prev key', mutate((r) => { delete r.prev; })],
    ['missing adoptedTick', mutate((r) => { delete r.adoptedTick; })],
    ['extra top-level key', mutate((r) => { r.extra = 1; })],
    ['cur missing', mutate((r) => { delete r.cur; })],
    ['cur null', mutate((r) => { r.cur = null; })],
    ['cur as an array', mutate((r) => { r.cur = []; })],
    ['extra key in cur', mutate((r) => { sub(r, 'cur').x = 1; })],
    ['cur missing trust', mutate((r) => { delete sub(r, 'cur').trust; })],
    ['negative epoch', mutate((r) => { sub(r, 'cur').e = -1; })],
    ['fractional epoch', mutate((r) => { sub(r, 'cur').e = 11.5; })],
    ['epoch above the safe range', mutate((r) => { sub(r, 'cur').e = 2 ** 53; })],
    ['epoch as a string', mutate((r) => { sub(r, 'cur').e = '11'; })],
    ['upper-case hex', mutate((r) => { sub(r, 'cur').know = H(3).toUpperCase(); })],
    ['63-char secret', mutate((r) => { sub(r, 'cur').know = H(3).slice(1); })],
    ['65-char secret', mutate((r) => { sub(r, 'cur').trust = H(4) + '0'; })],
    ['non-hex secret', mutate((r) => { sub(r, 'cur').know = 'zz' + H(3).slice(2); })],
    ['identical know and trust', mutate((r) => { sub(r, 'cur').trust = sub(r, 'cur').know; })],
    ['prev not an object', mutate((r) => { r.prev = 5; })],
    ['prev epoch equal to cur', mutate((r) => { sub(r, 'prev').e = sub(r, 'cur').e; })],
    ['prev epoch above cur', mutate((r) => { sub(r, 'prev').e = (sub(r, 'cur').e as number) + 1; })],
    ['prev identical fields', mutate((r) => { sub(r, 'prev').trust = sub(r, 'prev').know; })],
    ['negative adoptedTick', mutate((r) => { r.adoptedTick = -1; })],
    ['fractional adoptedTick', mutate((r) => { r.adoptedTick = 1.5; })],
  ];
  for (const [name, raw] of bad) assert.equal(restoreEpochRecord(raw), null, name);
  assert.deepEqual(restoreEpochRecord(JSON.stringify(good)), good, 'the control (unmutated) restores');
});
