// src/lib/headless/send-attempts.test.ts
// Run: npx tsx --test src/lib/headless/send-attempts.test.ts
//
// sealed-send-death-001 anchors: the send-side journal names silent deaths.
//   A1 intent + deposited outcome      → 'deposited'
//   A2 intent + not-deposited outcome  → 'not-sent' (named refusal/throw)
//   A3 intent ALONE                    → 'corpse' — the wound class: send died
//      mid-flight leaving no row anywhere else
//   A4 outcome without intent (raw deposit / route hop) → still audited
//   A5 torn/foreign JSONL lines        → tolerated, never fatal
//   A6 re-send of the same note_id     → latest outcome wins

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { appendAttempt, parseAttempts, auditAttempts, attemptsPath, type SendAttempt } from './send-attempts';

const FP = 'cbb1738a8cd1d39d44cd2884885bc2304b358f3d198d237a8e106a4d2485f728';
const MBX = 'mailbox-deadbeef';

const intent = (id: string, extra: Partial<SendAttempt> = {}): SendAttempt =>
  ({ kind: 'intent', note_id: id, peer_fp: FP, mailbox_id: MBX, ts: '2026-10-28T01:26:00Z', wire: 'sealed', body_bytes: 5, recipient: 'peter', ...extra });
const outcome = (id: string, extra: Partial<SendAttempt> = {}): SendAttempt =>
  ({ kind: 'outcome', note_id: id, peer_fp: FP, mailbox_id: MBX, ts: '2026-10-28T01:26:05Z', wire: 'sealed', ...extra });

test('A1: intent + deposited outcome audits deposited', () => {
  const rows = auditAttempts([intent('n1'), outcome('n1', { stage: 'deposited', deposited: true })]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, 'deposited');
  assert.equal(rows[0].peer_fp, FP);
  assert.equal(rows[0].mailbox_id, MBX);
});

test('A2: intent + failed outcome audits not-sent with the named error', () => {
  const rows = auditAttempts([intent('n1'), outcome('n1', { stage: 'unreachable', deposited: false, error: 'fetch failed' })]);
  assert.equal(rows[0].state, 'not-sent');
  assert.equal(rows[0].error, 'fetch failed');
});

test('A3: intent with NO outcome audits corpse — the silent-death class', () => {
  const rows = auditAttempts([intent('n1')]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, 'corpse');
  assert.equal(rows[0].body_bytes, 5, 'corpse carries the body LENGTH (the resend copy is the store row under the same note_id)');
  assert.equal('body' in rows[0], false, 'never the body');
});

test('A4: outcome-only record (raw deposit of a caller blob) still audits', () => {
  const rows = auditAttempts([{ kind: 'outcome', note_id: '', peer_fp: FP, mailbox_id: MBX, ts: 't', wire: 'deposit', stage: 'deposited', deposited: true }]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, 'deposited');
});

test('A5: torn JSONL + foreign lines are tolerated', () => {
  const text = [
    '{"kind":"intent","note_id":"n1","peer_fp":"' + FP + '","mailbox_id":"m","ts":"t"}',
    '{"kind":"outcome",',                      // torn
    '{"not":"an attempt"}',                    // foreign
    'plain garbage',
    '{"kind":"intent","note_id":"n2","peer_fp":"' + FP + '","mailbox_id":"m","ts":"t"}',
  ].join('\n');
  const recs = parseAttempts(text);
  assert.equal(recs.length, 2);
  const rows = auditAttempts(recs);
  assert.equal(rows.filter((r) => r.state === 'corpse').length, 2);
});

test('A6: re-sent note_id — latest outcome wins', () => {
  const rows = auditAttempts([
    intent('n1'),
    outcome('n1', { stage: 'unreachable', deposited: false }),
    outcome('n1', { stage: 'deposited', deposited: true, ts: '2026-10-28T02:00:00Z' }),
  ]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, 'deposited');
});

test('appendAttempt writes one JSONL line through the append callback', () => {
  const lines: string[] = [];
  appendAttempt((l) => lines.push(l), intent('n1'));
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).kind, 'intent');
});

test('attemptsPath resolves inside the agent dir', () => {
  assert.equal(attemptsPath('/x/agent/'), '/x/agent/send-attempts.jsonl');
  assert.equal(attemptsPath('/x/agent'), '/x/agent/send-attempts.jsonl');
});

test('journal privacy (Flint #189121): no intent call in devin-comm passes the body; each records body_bytes + recipient instead', () => {
  const src = readFileSync(join(__dirname, '../../../scripts/devin-comm.ts'), 'utf8');
  const intents = src.split('\n').filter((l) => l.includes("kind: 'intent'"));
  assert.ok(intents.length >= 3);
  for (const l of intents) {
    assert.doesNotMatch(l, /[,{]\s*body\s*[,}]/, 'no body field: ' + l.trim().slice(0, 80));
    assert.doesNotMatch(l, /sha256|createHash/i, 'nothing derived from the body');
    assert.match(l, /body_bytes: Buffer\.byteLength\(body, 'utf8'\)/);
  }
});

test('journal retention: pruneAttempts keeps the last 14 days and drops torn lines', async () => {
  const { pruneAttempts } = await import('./send-attempts');
  const now = Date.parse('2026-10-31T20:00:00.000Z');
  const old = JSON.stringify({ kind: 'intent', note_id: 'a', peer_fp: 'f', mailbox_id: 'm', ts: '2026-10-01T00:00:00.000Z' });
  const fresh = JSON.stringify({ kind: 'outcome', note_id: 'b', peer_fp: 'f', mailbox_id: 'm', ts: '2026-10-30T00:00:00.000Z' });
  const out = pruneAttempts([old, '{torn', fresh].join('\n'), now);
  assert.equal(out.trim().split('\n').length, 1);
  assert.match(out, /"note_id":"b"/);
});
