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
