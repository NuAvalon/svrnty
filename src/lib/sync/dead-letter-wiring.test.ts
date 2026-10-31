// src/lib/sync/dead-letter-wiring.test.ts
// #720: the REAL wiring between consume's ack door and the app: (1) the note seam reports WHY a note was dropped and carries a fingerprint
// only for the reasons that come after authentication; (2) the FE dead-letter sink refuses to touch a notes store that is not open FOR THIS
// OWNER (a record must never land in another identity's DB); (3) the app's consume deps really include the sink.
// Run: npx tsx --test src/lib/sync/dead-letter-wiring.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildDeadLetterSink, buildNoteSeam, type NoteSeamDeps } from './live-book-poll';
import type { OwnerIdentity } from './consume-mailbox';

const OWNER_FP = 'aa'.repeat(32);
const OTHER_FP = 'bb'.repeat(32);
const SENDER_FP = 'cd'.repeat(32);
const owner = { fingerprint: OWNER_FP, privateKeyArmored: 'unused', passphrase: 'unused' } as unknown as OwnerIdentity;
const wire = { from_fingerprint: SENDER_FP } as never;

function seamDropping(reason: 'unverified' | 'not-in-book' | 'ratchet-unopenable' | undefined) {
  const deps: NoteSeamDeps = {
    openOwner: () => OWNER_FP,
    accept: (async (a: { onDrop?: (r: string) => void }) => {
      if (reason) a.onDrop?.(reason);
      return null;
    }) as unknown as NoteSeamDeps['accept'],
  };
  return buildNoteSeam(owner, deps);
}

test('W1 the note seam reports an UNVERIFIED drop with NO fingerprint (the claimed sender is attacker-controlled until authenticated)', async () => {
  const out = await seamDropping('unverified').accept(wire);
  assert.deepEqual(out, { dropped: 'unverified' });
  assert.equal('fp' in (out as object), false);
});

test('W2 the seam carries the sender fingerprint for the two drops that come AFTER authentication', async () => {
  assert.deepEqual(await seamDropping('not-in-book').accept(wire), { dropped: 'not-in-book', fp: SENDER_FP });
  assert.deepEqual(await seamDropping('ratchet-unopenable').accept(wire), { dropped: 'ratchet-unopenable', fp: SENDER_FP });
});

test('W3 a drop with no reason stays a plain null (legacy), and an accepted note is mapped exactly as before', async () => {
  assert.equal(await seamDropping(undefined).accept(wire), null);
  const seam = buildNoteSeam(owner, { openOwner: () => OWNER_FP, accept: (async () => ({ note_id: 'n1', thread_id: 't1', from_fingerprint: 'ff' })) as unknown as NoteSeamDeps['accept'] });
  assert.deepEqual(await seam.accept(wire), { note_id: 'n1', thread_id: 't1', from_fingerprint: 'ff' });
});

const row = { envelope_id: 'e1', first_seen: '2026-10-30T12:00:00.000Z', reason: 'decrypt-failed', blob_kind: 'other' } as never;

test('W4 the FE dead-letter sink refuses when the notes store is open for ANOTHER owner or locked: record, clear and settle all throw before touching the store', async () => {
  for (const open of [OTHER_FP, null]) {
    const sink = buildDeadLetterSink(owner, () => open);
    await assert.rejects(() => sink.record(row), /not open for this owner/);
    await assert.rejects(() => sink.clear('e1'), /not open for this owner/);
    await assert.rejects(() => sink.settle!(), /not open for this owner/);
  }
});

test('W5 static: the app consume deps include the sink (so the door is live in the PWA), and headless records too (#713, Flint #189046)', () => {
  const lbp = readFileSync(new URL('./live-book-poll.ts', import.meta.url), 'utf8');
  assert.match(lbp, /deadLetter: buildDeadLetterSink\(owner\)/);
  // Headless has no IndexedDB, so its sink is a metadata file in the agent dir (headless-dead-letter.ts); without it a headless loss was
  // only COUNTED. The sink is opt-in by path, and the CLI always passes it (headless-dead-letter.test D6).
  const headless = readFileSync(new URL('../headless/headless-client.ts', import.meta.url), 'utf8');
  assert.match(headless, /deadLetter: opts\.deadLetterPath \? headlessDeadLetterSink\(opts\.deadLetterPath\) : undefined/);
});
