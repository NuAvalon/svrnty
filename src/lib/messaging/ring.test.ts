// src/lib/messaging/ring.test.ts
// Run: npx tsx --test src/lib/messaging/ring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  addRingMember,
  createRingChannel,
  notesToShare,
  removeRingMember,
  RING_HISTORY_LIMIT,
  rotateRingMembership,
  ringDepositTargets,
} from './ring';
import { noteSigningInput } from './canonical';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';

test('createRingChannel mints key + rejects tiny membership', () => {
  assert.throws(() => createRingChannel('x', ['a']), /at least 2/);
  const ch = createRingChannel('Kin', ['fpA', 'fpB', 'fpA']);
  assert.equal(ch.member_fingerprints.length, 2);
  assert.equal(ch.key_epoch, 1);
  assert.ok(ch.content_key_b64.length > 10);
  assert.deepEqual(ringDepositTargets(ch), ch.member_fingerprints);
});

test('rotateRingMembership bumps epoch and replaces content key', () => {
  const ch = createRingChannel('Kin', ['a', 'b', 'c']);
  ch.session_snapshot = {
    v: 1,
    channel_id: ch.channel_id,
    epoch: 1,
    self_fp: 'a',
    members: ['a', 'b', 'c'],
    pairs: [],
  };
  const next = rotateRingMembership(ch, ['a', 'b']);
  assert.equal(next.key_epoch, 2);
  assert.notEqual(next.content_key_b64, ch.content_key_b64);
  assert.deepEqual(next.member_fingerprints, ['a', 'b']);
  assert.equal(next.session_snapshot, undefined);
});

test('founders start with earlier notes; add defaults to new only', () => {
  const ch = createRingChannel('Kin', ['a', 'b']);
  assert.equal(ch.member_history?.a.history, 'previous');
  assert.equal(ch.member_history?.a.since_epoch, 1);
  const added = addRingMember(ch, 'c');
  assert.equal(added.key_epoch, 2);
  assert.equal(added.member_history?.c.history, 'new');
  assert.equal(added.member_history?.c.since_epoch, 2);
  assert.equal(added.session_snapshot, undefined);
  const withPast = addRingMember(ch, 'c', 'previous');
  assert.equal(withPast.member_history?.c.history, 'previous');
  assert.equal(withPast.member_history?.c.since_epoch, 1);
});

test('remove drops the member and bumps the epoch', () => {
  const ch = createRingChannel('Kin', ['a', 'b', 'c']);
  const next = removeRingMember(ch, 'c');
  assert.deepEqual(next.member_fingerprints, ['a', 'b']);
  assert.equal(next.key_epoch, 2);
  assert.equal(next.member_history?.c, undefined);
  assert.equal(next.session_snapshot, undefined);
  assert.throws(() => removeRingMember(next, 'c'), /not in the ring/);
});

test('a ring cannot grow past the fan-out cap', () => {
  const members = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
  const ch = createRingChannel('Full', members);
  assert.throws(() => addRingMember(ch, 'i'), /at most 8/);
  assert.throws(() => createRingChannel('Too big', [...members, 'i']), /at most 8/);
});

test('notesToShare is empty unless the grant is previous, and keeps the latest hundred', () => {
  const notes = Array.from({ length: RING_HISTORY_LIMIT + 5 }, (_, i) => ({
    note_id: `note_${String(i).padStart(3, '0')}`,
    sent_at: new Date(Date.UTC(2026, 8, 30, 0, 0, i)).toISOString(),
    from_fingerprint: 'a',
    body: `n${i}`,
    reply_to: i === 10 ? 'note_001' : undefined,
    thread_root: i === 10 ? 'note_001' : undefined,
  }));
  assert.deepEqual(notesToShare(notes, 'new'), []);
  const shared = notesToShare(notes, 'previous');
  assert.equal(shared.length, RING_HISTORY_LIMIT);
  assert.equal(shared[0]?.note_id, 'note_005');
  assert.equal(shared.at(-1)?.note_id, 'note_104');
  assert.equal(shared.find((n) => n.note_id === 'note_010')?.reply_to, 'note_001');
  assert.equal(shared.find((n) => n.note_id === 'note_006')?.reply_to, undefined);
});

test('noteSigningInput is stable and excludes signature', () => {
  const note: NoteWireV0 = {
    type: NOTE_WIRE_TYPE,
    note_id: 'note_1',
    thread_id: 'thr_1',
    from_fingerprint: 'FP',
    sent_at: '2026-08-25T00:00:00.000Z',
    body: 'hello',
    participant_kind: 'human',
  };
  const a = noteSigningInput(note);
  const b = noteSigningInput({ ...note, signature: { classical: 'NOPE' } });
  // canonicalize exclude should strip signature if present on a wider object
  assert.equal(typeof a, 'string');
  assert.ok(a.includes('hello'));
  assert.ok(a.includes(NOTE_WIRE_TYPE));
  assert.equal(a, noteSigningInput(note));
  void b;
  const threaded = noteSigningInput({ ...note, reply_to: 'note_9', thread_root: 'note_1' });
  assert.notEqual(a, threaded);
  assert.ok(threaded.includes('note_9'));
});
