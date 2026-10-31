// src/components/notes/ratchet-rows-view.test.ts
// #720: the per-contact thread view-model. Pure. Run: npx tsx --test src/components/notes/ratchet-rows-view.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { DeadLetterRow } from '@/lib/sync/dead-letter';
import { namedRow } from './ratchet-rows';
import { readFileSync } from 'node:fs';
import { inputFor, ratchetViewFor } from './ratchet-rows-view';
import { RESET_FAILED_LINE } from './ratchet-reset-copy';

const PEER = 'ab'.repeat(32), OTHER = 'cd'.repeat(32);
let n = 0;
const row = (o: Partial<DeadLetterRow>): DeadLetterRow => ({ envelope_id: `env-${++n}`, first_seen: '2026-10-31T10:00:00.000Z', reason: 'ratchet-local', blob_kind: 'json', fp: PEER, ...o });

test('R1 only this contact\'s ratchet rows, fp compared case-insensitively; other contacts and non-ratchet reasons are ignored', () => {
  const v = ratchetViewFor([
    row({ reason: 'ratchet-desync', phase: 'held' }),
    row({ reason: 'ratchet-desync', phase: 'held', fp: OTHER }),
    row({ reason: 'missing-key', phase: 'held' }), row({ reason: 'not-in-book' }), row({ reason: 'decrypt-failed', fp: undefined }),
  ], PEER.toUpperCase(), 'Sam', false);
  assert.deepEqual(v.rows.map((r) => r.line), [namedRow('Sam', { kind: 'desync', phase: 'held' }).line]);
});

test('R2 every ratchet reason maps to Athena\'s copy for it, and the reset flag changes ONLY a first-frame-rejected verdict', () => {
  const cases: Array<[Partial<DeadLetterRow>, boolean, ReturnType<typeof namedRow>]> = [
    [{ reason: 'ratchet-local', phase: 'held' }, false, namedRow('Sam', { kind: 'local', phase: 'held' })],
    [{ reason: 'ratchet-local', phase: 'recorded' }, true, namedRow('Sam', { kind: 'local', phase: 'recorded' })],
    [{ reason: 'ratchet-desync', phase: 'recorded' }, true, namedRow('Sam', { kind: 'desync', phase: 'recorded' })],
    [{ reason: 'ratchet-unopenable', cause: 'malformed-frame' }, true, namedRow('Sam', { kind: 'verdict', firstFrameRejected: false, outOfStep: false })],
    [{ reason: 'ratchet-unopenable', cause: 'first-frame-rejected' }, false, namedRow('Sam', { kind: 'verdict', firstFrameRejected: true, outOfStep: false })],
    [{ reason: 'ratchet-unopenable', cause: 'first-frame-rejected' }, true, namedRow('Sam', { kind: 'verdict', firstFrameRejected: true, outOfStep: true })],
    [{ reason: 'ratchet-unopenable' }, true, namedRow('Sam', { kind: 'verdict', firstFrameRejected: false, outOfStep: false })],
    [{ reason: 'session-reset' }, true, namedRow('Sam', { kind: 'session-reset' })],
  ];
  for (const [o, flag, want] of cases) {
    const v = ratchetViewFor([row(o)], PEER, 'Sam', flag);
    assert.equal(v.rows.length, 1, JSON.stringify(o));
    assert.equal(v.rows[0].line, want.line, JSON.stringify([o, flag]));
    assert.equal(v.rows[0].hint, want.hint);
  }
  const out = ratchetViewFor([row({ reason: 'ratchet-unopenable', cause: 'first-frame-rejected' })], PEER, 'Sam', true).rows[0].line;
  assert.match(out, /out of step/, 'the flag + first-frame-rejected = the out-of-step line');
  assert.doesNotMatch(ratchetViewFor([row({ reason: 'ratchet-unopenable', cause: 'malformed-frame' })], PEER, 'Sam', true).rows[0].line, /out of step/, 'the flag does not touch another cause');
});

test('R3 identical lines collapse to ONE row (the copy names no count, so none is invented); different rows stay; newest first', () => {
  const v = ratchetViewFor([
    row({ reason: 'ratchet-desync', phase: 'held', first_seen: '2026-10-31T09:00:00.000Z' }),
    row({ reason: 'ratchet-desync', phase: 'held', first_seen: '2026-10-31T09:30:00.000Z' }),
    row({ reason: 'ratchet-desync', phase: 'held', first_seen: '2026-10-31T09:45:00.000Z' }),
    row({ reason: 'session-reset', first_seen: '2026-10-31T11:00:00.000Z' }),
  ], PEER, 'Sam', false);
  assert.equal(v.rows.length, 2);
  assert.equal(v.rows[0].line, namedRow('Sam', { kind: 'session-reset' }).line, 'newest first');
  assert.equal(new Set(v.rows.map((r) => r.key)).size, 2);
});

test('R4 a holdable row with no phase reads as RECORDED, never "we will keep trying"', () => {
  assert.deepEqual(inputFor(row({ reason: 'ratchet-local' }), false), { kind: 'local', phase: 'recorded' });
  assert.deepEqual(inputFor(row({ reason: 'ratchet-desync', phase: 'held' }), false), { kind: 'desync', phase: 'held' });
  assert.equal(inputFor(row({ reason: 'missing-key' }), false), null);
});

test('R5 held count = frames still held for THIS contact; the reset is offered only after a real ratchet failure, never for a healthy thread or an already-reset one', () => {
  const rows = [row({ reason: 'ratchet-desync', phase: 'held' }), row({ reason: 'ratchet-local', phase: 'held' }), row({ reason: 'ratchet-local', phase: 'recorded' }), row({ reason: 'ratchet-desync', phase: 'held', fp: OTHER })];
  const v = ratchetViewFor(rows, PEER, 'Sam', false);
  assert.equal(v.held, 2); assert.equal(v.canReset, true);
  assert.equal(ratchetViewFor([], PEER, 'Sam', false).canReset, false, 'healthy thread');
  assert.equal(ratchetViewFor([], PEER, 'Sam', true).canReset, false, 'the flag alone names nothing to reset');
  assert.equal(ratchetViewFor([row({ reason: 'session-reset' })], PEER, 'Sam', true).canReset, false, 'only a record of a reset already done');
  assert.equal(ratchetViewFor([row({ reason: 'ratchet-desync', phase: 'held', fp: OTHER })], PEER, 'Sam', false).canReset, false, 'another contact\'s failure');
});

test('R6 nothing from a record but fixed copy reaches the view: an envelope id never appears in a line, hint or key', () => {
  const r = row({ reason: 'ratchet-desync', phase: 'held', envelope_id: 'SECRET-ENVELOPE-ID-123' });
  const v = ratchetViewFor([r], PEER, 'Sam', false);
  assert.doesNotMatch(JSON.stringify(v), /SECRET-ENVELOPE-ID-123/);
});

test('R7 the reset-failed line is copy v0.11 by value, never claims the reset did not happen, and the component takes it from the copy file (no inline string)', () => {
  assert.equal(RESET_FAILED_LINE, "The reset didn't finish. Try again.");
  assert.doesNotMatch(RESET_FAILED_LINE, /couldn't reset|failed|safe|kept|\d/i);
  const comp = readFileSync(new URL('./RatchetRows.tsx', import.meta.url), 'utf8');
  assert.match(comp, /import \{ RESET_FAILED_LINE \} from '\.\/ratchet-reset-copy';/);
  assert.doesNotMatch(comp, /export const RESET_FAILED_LINE|Couldn't reset right now/, 'no provisional line left in the component');
  assert.equal((comp.match(/RESET_FAILED_LINE/g) ?? []).length, 2, 'imported once, rendered once');
});
