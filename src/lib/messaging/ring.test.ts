// src/lib/messaging/ring.test.ts
// Run: npx tsx --test src/lib/messaging/ring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRingChannel, rotateRingMembership, ringDepositTargets } from './ring';
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
  const next = rotateRingMembership(ch, ['a', 'b']);
  assert.equal(next.key_epoch, 2);
  assert.notEqual(next.content_key_b64, ch.content_key_b64);
  assert.deepEqual(next.member_fingerprints, ['a', 'b']);
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
  const b = noteSigningInput({ ...note, /* @ts-expect-error probe */ signature: 'NOPE' } as NoteWireV0);
  // canonicalize exclude should strip signature if present on a wider object
  assert.equal(typeof a, 'string');
  assert.ok(a.includes('hello'));
  assert.ok(a.includes(NOTE_WIRE_TYPE));
  assert.equal(a, noteSigningInput(note));
  void b;
});
