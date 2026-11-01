// src/components/notes/ratchet-rows-view.test.ts
// #720: the per-contact thread view-model. Pure. Run: npx tsx --test src/components/notes/ratchet-rows-view.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { DeadLetterRow } from '@/lib/sync/dead-letter';
import { namedRow } from './ratchet-rows';
import { readFileSync } from 'node:fs';
import { inputFor, peerIsAgent, ratchetViewFor, resetOffered } from './ratchet-rows-view';
import { RESET_FAILED_LINE, RESET_UNAVAILABLE_HINT_HELD, RESET_UNAVAILABLE_HINT_RECORDED } from './ratchet-reset-copy';

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

const HELD = (o: Partial<DeadLetterRow> = {}) => row({ reason: 'ratchet-desync', phase: 'held', ...o });
const RECORDED = (o: Partial<DeadLetterRow> = {}) => row({ reason: 'ratchet-desync', phase: 'recorded', ...o });

test('A1 an AGENT contact: no Reset, and the two desync hints say so instead of pointing at a button that is not there (copy v0.12, by value); the lines are unchanged', () => {
  const v = ratchetViewFor([HELD(), RECORDED()], PEER, 'Sam', false, true);
  assert.equal(v.canReset, false);
  const heldNamed = namedRow('Sam', { kind: 'desync', phase: 'held' }), recNamed = namedRow('Sam', { kind: 'desync', phase: 'recorded' });
  const byLine = new Map(v.rows.map((r) => [r.line, r.hint]));
  assert.equal(byLine.get(heldNamed.line), RESET_UNAVAILABLE_HINT_HELD);
  assert.equal(byLine.get(recNamed.line), RESET_UNAVAILABLE_HINT_RECORDED);
  assert.equal(RESET_UNAVAILABLE_HINT_HELD, "Resetting the message session isn't available for this contact yet.");
  assert.equal(RESET_UNAVAILABLE_HINT_RECORDED, "This app couldn't keep the message itself, only a note that it arrived. Resetting the message session isn't available for this contact yet.");
  for (const r of v.rows) assert.doesNotMatch(`${r.line} ${r.hint}`, /reset your message session|you can reset|ask \S+ to send it again/i, 'no pointer to the missing button, no resend advice');
  assert.equal(v.held, 1, 'the held count is still the true number: one held record, the recorded one is not held');
});

test('A2 a HUMAN contact: the button is offered and Athena\'s v0.9 hints are untouched (the other direction of A1)', () => {
  const v = ratchetViewFor([HELD(), RECORDED()], PEER, 'Sam', false, false);
  assert.equal(v.canReset, true);
  const hints = v.rows.map((r) => r.hint).sort();
  assert.deepEqual(hints, [namedRow('Sam', { kind: 'desync', phase: 'held' }).hint, namedRow('Sam', { kind: 'desync', phase: 'recorded' }).hint].sort());
  assert.ok(v.rows.some((r) => /reset your message session with them/i.test(r.hint ?? '')), 'the v0.9 hint still points at the button');
});

test('A3 for an agent contact every OTHER row is exactly Athena\'s copy (local, verdict, session-reset), and no row is dropped', () => {
  const cases: Array<[Partial<DeadLetterRow>, ReturnType<typeof namedRow>]> = [
    [{ reason: 'ratchet-local', phase: 'held' }, namedRow('Sam', { kind: 'local', phase: 'held' })],
    [{ reason: 'ratchet-local', phase: 'recorded' }, namedRow('Sam', { kind: 'local', phase: 'recorded' })],
    [{ reason: 'ratchet-unopenable', cause: 'malformed-frame' }, namedRow('Sam', { kind: 'verdict', firstFrameRejected: false, outOfStep: false })],
    [{ reason: 'session-reset' }, namedRow('Sam', { kind: 'session-reset' })],
  ];
  for (const [o, want] of cases) {
    const v = ratchetViewFor([row(o)], PEER, 'Sam', false, true);
    assert.equal(v.rows.length, 1);
    assert.deepEqual([v.rows[0].line, v.rows[0].hint], [want.line, want.hint], JSON.stringify(o));
  }
});

test('A4 resetOffered is the one predicate: failed AND not an agent', () => {
  assert.equal(resetOffered(true, false), true);
  assert.equal(resetOffered(true, true), false);
  assert.equal(resetOffered(false, false), false);
  assert.equal(resetOffered(false, true), false);
});

test('A5 peerIsAgent reads what this device stored: a direct-thread participant or a note FROM them that declared it; fp case-insensitive; others ignored', () => {
  const th = (fp: string, kind: 'human' | 'agent', tk: 'direct' | 'ring' = 'direct') => ({ kind: tk, participants: [{ fingerprint: fp, kind, display_name: 'x' }] });
  assert.equal(peerIsAgent([th(PEER, 'agent')], [], PEER.toUpperCase()), true);
  assert.equal(peerIsAgent([th(PEER, 'human')], [], PEER), false);
  assert.equal(peerIsAgent([th(OTHER, 'agent')], [], PEER), false, "another contact's thread");
  assert.equal(peerIsAgent([th(PEER, 'agent', 'ring')], [], PEER), false, 'a ring thread is not a statement about the direct contact');
  assert.equal(peerIsAgent([], [{ from_fingerprint: PEER, participant_kind: 'agent' }], PEER), true);
  assert.equal(peerIsAgent([], [{ from_fingerprint: OTHER, participant_kind: 'agent' }], PEER), false);
  assert.equal(peerIsAgent([], [], PEER), false, 'unknown reads as human (the wire default), and the doc says this is not a security check');
});

test('A6 static: the component hands the flag to the view-model and NotesInbox computes it from threads + notes', () => {
  assert.match(readFileSync(new URL('./RatchetRows.tsx', import.meta.url), 'utf8'), /ratchetViewFor\(records, peerFingerprint, peerName, outOfStep, agentContact\)/);
  assert.match(readFileSync(new URL('./NotesInbox.tsx', import.meta.url), 'utf8'), /agentContact=\{peerIsAgent\(threads, notes, selectedFp\)\}/);
  assert.match(readFileSync(new URL('./ratchet-rows-view.ts', import.meta.url), 'utf8'), /NOT a security check/);
});

test('A7 (Hypatia #2486) the reset flag never gives an AGENT contact the "out of step ... should bring them back" line: it reads the plain verdict line; a human with the flag still gets it', () => {
  const r = () => [row({ reason: 'ratchet-unopenable', cause: 'first-frame-rejected' })];
  const agent = ratchetViewFor(r(), PEER, 'Sam', true, true).rows[0];
  const plain = namedRow('Sam', { kind: 'verdict', firstFrameRejected: true, outOfStep: false });
  assert.deepEqual([agent.line, agent.hint], [plain.line, plain.hint]);
  assert.doesNotMatch(agent.line, /out of step|bring them back/i);
  assert.match(ratchetViewFor(r(), PEER, 'Sam', true, false).rows[0].line, /out of step/, 'the human direction is unchanged');
});
