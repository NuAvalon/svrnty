// #720 reset step 2(i): the PHASE of a dead-letter row. 'held' = the envelope is still on the relay and this app keeps trying; 'recorded' = it is
// not any more. Only the reasons that can be HELD carry a phase; everything else is a verdict, recorded by definition.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HOLDABLE_REASONS, DEAD_LETTER_REASONS, makeDeadLetterRow, parseDeadLetterRow, type DeadLetterReason } from './dead-letter';

const FP = 'cd'.repeat(32);
const T = '2026-10-30T12:00:00.000Z';
const base = { envelope_id: 'e1', first_seen: T, blob_kind: 'other' } as const;

test('PH1 the holdable reasons are exactly missing-key, ratchet-local, ratchet-desync (a test pins the list so it cannot grow by accident)', () => {
  assert.deepEqual([...HOLDABLE_REASONS].sort(), ['missing-key', 'ratchet-desync', 'ratchet-local']);
});

test('PH2 parse accepts held / recorded on a holdable reason and returns it', () => {
  for (const reason of HOLDABLE_REASONS) for (const phase of ['held', 'recorded'] as const) {
    const fp = reason === 'missing-key' ? {} : { fp: FP };
    assert.equal(parseDeadLetterRow({ ...base, reason, phase, ...fp })?.phase, phase, `${reason}/${phase}`);
  }
});

test('PH3 parse REFUSES a phase on every non-holdable reason (a verdict has no phase), an unknown phase value, and a non-string phase', () => {
  for (const reason of DEAD_LETTER_REASONS.filter((r) => !HOLDABLE_REASONS.has(r as DeadLetterReason))) {
    assert.equal(parseDeadLetterRow({ ...base, reason, phase: 'held' }), null, `${reason} must not carry a phase`);
  }
  for (const phase of ['HELD', 'kept', '', null, 1, {}, ['held']]) {
    assert.equal(parseDeadLetterRow({ ...base, reason: 'ratchet-desync', fp: FP, phase }), null, JSON.stringify(phase));
  }
});

test('PH4 a row with NO phase still parses (rows written before the field), and the exact key set is still enforced', () => {
  const r = parseDeadLetterRow({ ...base, reason: 'ratchet-desync', fp: FP });
  assert.ok(r); assert.equal(r!.phase, undefined);
  assert.equal(parseDeadLetterRow({ ...base, reason: 'ratchet-desync', fp: FP, phase: 'held', extra: 1 }), null);
});

test('PH5 makeDeadLetterRow carries the phase only for a holdable reason, and only a valid one', () => {
  const mk = (reason: DeadLetterReason, phase: unknown) => makeDeadLetterRow({ envelopeId: 'e1', firstSeen: T, reason, blob: 'x', fp: FP, phase: phase as never });
  assert.equal(mk('ratchet-desync', 'held')?.phase, 'held');
  assert.equal(mk('ratchet-local', 'recorded')?.phase, 'recorded');
  assert.equal(mk('missing-key', 'held')?.phase, 'held');
  assert.equal(mk('unknown-format', 'held')?.phase, undefined, 'a verdict never gets a phase');
  assert.equal(mk('ratchet-desync', 'bogus')?.phase, undefined);
  assert.equal(mk('ratchet-desync', undefined)?.phase, undefined);
  assert.ok(parseDeadLetterRow(mk('ratchet-desync', 'held')), 'what make builds, parse accepts');
});

// ── R2 (reset releases that contact's HELD frames) ──
import { heldCountFor, resetMarksFor, type DeadLetterRow } from './dead-letter';
const FP2 = 'ab'.repeat(32);
const row = (id: string, reason: DeadLetterReason, fp: string | undefined, phase?: 'held' | 'recorded'): DeadLetterRow =>
  parseDeadLetterRow({ envelope_id: id, first_seen: T, reason, blob_kind: 'other', ...(fp ? { fp } : {}), ...(phase ? { phase } : {}) })!;

test('RS1 heldCountFor counts ONLY that contact\'s HELD ratchet-local / ratchet-desync rows (not recorded, not other contacts, not missing-key, not verdicts)', () => {
  const rows = [
    row('a', 'ratchet-desync', FP, 'held'), row('b', 'ratchet-local', FP, 'held'),
    row('c', 'ratchet-desync', FP, 'recorded'), row('d', 'ratchet-desync', FP2, 'held'),
    row('e', 'missing-key', undefined, 'held'), row('f', 'ratchet-unopenable', FP), row('g', 'session-reset', FP),
  ];
  assert.equal(heldCountFor(rows, FP), 2);
  assert.equal(heldCountFor(rows, FP2), 1);
  assert.equal(heldCountFor(rows, FP.toUpperCase()), 2, 'fingerprint case does not matter');
  assert.equal(heldCountFor(rows, 'ee'.repeat(32)), 0);
});

test('RS2 resetMarksFor rewrites exactly those held rows as session-reset verdicts (same id + first_seen + fp, NO phase), and touches nothing else', () => {
  const rows = [row('a', 'ratchet-desync', FP, 'held'), row('b', 'ratchet-local', FP, 'held'), row('c', 'ratchet-desync', FP2, 'held'), row('d', 'ratchet-desync', FP, 'recorded')];
  const marks = resetMarksFor(rows, FP);
  assert.deepEqual(marks.map((m) => m.envelope_id).sort(), ['a', 'b']);
  for (const m of marks) {
    assert.equal(m.reason, 'session-reset'); assert.equal(m.fp, FP); assert.equal(m.first_seen, T); assert.equal(m.phase, undefined);
    assert.ok(parseDeadLetterRow(m), 'a mark is a valid row');
  }
  assert.deepEqual(resetMarksFor(rows, 'ee'.repeat(32)), []);
});
