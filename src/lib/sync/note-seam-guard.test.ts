// N10 cross-tab hardening — the note-seam accept() must refuse unless the notes store is open FOR THIS owner.
// Proves the WIRING (accept really calls the guard), not just the predicate (notes-owner-guard.test.ts).
//
// Run: npx tsx --test src/lib/sync/note-seam-guard.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNoteSeam, type NoteSeamDeps } from './live-book-poll';
import type { OwnerIdentity } from './consume-mailbox';

const OWNER_FP = 'aa'.repeat(32);
const OTHER_FP = 'bb'.repeat(32);

const owner = {
  fingerprint: OWNER_FP,
  privateKeyArmored: 'unused-in-accept-path',
  passphrase: 'unused-in-accept-path',
} as unknown as OwnerIdentity;

function harness(openOwner: string | null) {
  let innerCalls = 0;
  const deps: NoteSeamDeps = {
    openOwner: () => openOwner,
    accept: (async () => {
      innerCalls++;
      return { note_id: 'n1', thread_id: 't1', from_fingerprint: 'ff' };
    }) as unknown as NoteSeamDeps['accept'],
  };
  return { seam: buildNoteSeam(owner, deps), calls: () => innerCalls };
}

const wire = {} as never;

test('store open for ANOTHER owner → accept throws (retryable) and never reaches the inner accept', async () => {
  const { seam, calls } = harness(OTHER_FP);
  await assert.rejects(() => seam.accept(wire), /not open for this owner/);
  assert.equal(calls(), 0);
});

test('store LOCKED (null owner) → accept throws and never reaches the inner accept', async () => {
  const { seam, calls } = harness(null);
  await assert.rejects(() => seam.accept(wire), /not open for this owner/);
  assert.equal(calls(), 0);
});

test('store open for THIS owner → accept proceeds to the inner accept and maps the record', async () => {
  const { seam, calls } = harness(OWNER_FP);
  const out = await seam.accept(wire);
  assert.equal(calls(), 1);
  assert.deepEqual(out, { note_id: 'n1', thread_id: 't1', from_fingerprint: 'ff' });
});

test('unlock cycle ENDED (lock landed after verify) → accept throws and never reaches the inner accept', async () => {
  let innerCalls = 0;
  const deadOwner = { ...owner, cycle: { ended: true } } as unknown as OwnerIdentity;
  const seam = buildNoteSeam(deadOwner, {
    openOwner: () => OWNER_FP, // store looks open; only the cycle is dead
    accept: (async () => { innerCalls++; return null; }) as unknown as NoteSeamDeps['accept'],
  });
  await assert.rejects(() => seam.accept(wire), /unlock cycle ended/);
  assert.equal(innerCalls, 0);
});
