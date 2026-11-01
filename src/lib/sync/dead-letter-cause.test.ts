// src/lib/sync/dead-letter-cause.test.ts
// #720 cause-on-row: WHY a ratchet frame did not open, as a fixed token on the record. Closed list; only the three ratchet reasons carry one;
// anything else is dropped at write and refused at read. Run: npx tsx --test src/lib/sync/dead-letter-cause.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CAUSE_REASONS, DEAD_LETTER_CAUSES, DEAD_LETTER_REASONS, makeDeadLetterRow, parseDeadLetterRow, resetMarksFor, type DeadLetterReason, type DeadLetterRow } from './dead-letter';

const FP = 'cd'.repeat(32);
const T = '2026-10-30T12:00:00.000Z';
const base = { envelope_id: 'e1', first_seen: T, blob_kind: 'other' } as const;

test('CA1 the cause list and the reasons that may carry one are exactly these (pinned so neither grows by accident)', () => {
  assert.deepEqual([...DEAD_LETTER_CAUSES].sort(), [
    'contact-missing-after-admit', 'first-frame-rejected', 'malformed-frame', 'no-ratchet-opener', 'open-threw', 'own-ratchet-identity-unavailable',
    'peer-card-has-no-pq-keys', 'ratchet-receive-failed', 'session-row-unreadable', 'session-snapshot-corrupt',
  ]);
  assert.deepEqual([...CAUSE_REASONS].sort(), ['ratchet-desync', 'ratchet-local', 'ratchet-unopenable']);
});

test('CA2 makeDeadLetterRow keeps a valid cause on the ratchet reasons only; an unknown or non-string cause, or any other reason, gets none', () => {
  for (const reason of DEAD_LETTER_REASONS) {
    const withCause = makeDeadLetterRow({ envelopeId: 'e1', firstSeen: T, reason, blob: 'x', fp: FP, cause: 'first-frame-rejected' });
    assert.equal(withCause?.cause, CAUSE_REASONS.has(reason as DeadLetterReason) ? 'first-frame-rejected' : undefined, reason);
  }
  for (const bad of ['EVIL text', '', 'First-Frame-Rejected', 42, null, {}, ['open-threw']]) {
    assert.equal(makeDeadLetterRow({ envelopeId: 'e1', firstSeen: T, reason: 'ratchet-local', blob: 'x', fp: FP, cause: bad })?.cause, undefined, String(bad));
  }
  assert.equal('cause' in makeDeadLetterRow({ envelopeId: 'e1', firstSeen: T, reason: 'ratchet-local', blob: 'x', fp: FP })!, false, 'no cause given = no key');
});

test('CA3 parse accepts a valid cause on a ratchet reason and REFUSES: a cause on any other reason, an unknown token, a non-string; a row without one still parses; the key set stays exact', () => {
  for (const reason of CAUSE_REASONS) for (const cause of DEAD_LETTER_CAUSES) assert.equal(parseDeadLetterRow({ ...base, reason, fp: FP, cause })?.cause, cause, `${reason}/${cause}`);
  for (const reason of DEAD_LETTER_REASONS.filter((r) => !CAUSE_REASONS.has(r as DeadLetterReason))) {
    assert.equal(parseDeadLetterRow({ ...base, reason, cause: 'open-threw' }), null, `${reason} must not carry a cause`);
  }
  for (const bad of ['EVIL text', '', 7, null, {}]) assert.equal(parseDeadLetterRow({ ...base, reason: 'ratchet-local', fp: FP, cause: bad }), null, String(bad));
  assert.ok(parseDeadLetterRow({ ...base, reason: 'ratchet-local', fp: FP }), 'a row written before the field');
  assert.equal(parseDeadLetterRow({ ...base, reason: 'ratchet-local', fp: FP, cause: 'open-threw', extra: 1 }), null);
});

test('CA4 a reset turns a HELD row into a session-reset record WITHOUT its cause (the reason says it all, and a session-reset row may not carry one)', () => {
  const held: DeadLetterRow = { ...base, reason: 'ratchet-desync', fp: FP, phase: 'held', cause: 'ratchet-receive-failed' };
  const [mark] = resetMarksFor([held], FP);
  assert.equal(mark.reason, 'session-reset'); assert.equal('cause' in mark, false);
  assert.ok(parseDeadLetterRow(mark));
});
