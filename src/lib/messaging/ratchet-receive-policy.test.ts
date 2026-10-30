// src/lib/messaging/ratchet-receive-policy.test.ts
//
// B group 2, commit 4b (Flint #439 acceptance): the RECEIVE-side ratchet policy.
//   R4  the advanced session is committed only AFTER the note it carried is durably stored. Before, the open persisted the
//       advance first; a store failure then left the envelope retryable but the session already past that message key, so the
//       retry could not open it and the message was lost although it sat safely in the mailbox.
//   R2  every session read/write is bound to the owner the caller acts for: a store left open for another identity (cross-tab
//       switch) or a locked one throws BEFORE touching a session, so a wrong-owner open never advances/creates/overwrites one.
// Real ratchet crypto + a real signed note wire (the real verifyNoteSender runs). Fakes: in-memory session storage with a log, and
// the note/thread stores with failures injected at each point where the order matters.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer, RatchetSnapshot } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { memIO } from './ratchet-test-io';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteRecord, NoteThread, NoteWireV0 } from './types';
import {
  sealDirectNote, openDirectNoteStaged, ownerBoundRatchetIO, chooseWireBody,
} from './direct-session';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });


type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };

const ME = 'fp-me', THEM = 'fp-them';

/** A note from THEM carrying a real ratchet frame, signed by a real identity, plus the receiver's state and flaky stores. */
async function scenario(opts: { failPutNote?: number; failPutThread?: number; failSessionPut?: number } = {}) {
  const me = ratchetIdentity(), them = ratchetIdentity();
  const sender = await mintHeadlessAgent({ throwaway: true });
  const frame = await sealDirectNote(ME, 'the secret message', them, peerOf(me), memIO().io);       // THEM -> ME, their first frame
  assert.ok(frame);
  const unsigned: NoteWireV0 = {
    type: NOTE_WIRE_TYPE, note_id: 'note_r4', thread_id: 'thr_r4', from_fingerprint: idOf(sender).fingerprint,
    sent_at: '2026-10-25T00:00:00.000Z', body: frame!, participant_kind: 'human',
  };
  const wire = await signNoteWire(unsigned, idOf(sender).public_key, sender.secret_material.classicalPrivateKey,
    sender.secret_material.classicalKpass, idOf(sender).pq_kem_public_key, idOf(sender).pq_sig_public_key);
  const session = memIO({ failPuts: opts.failSessionPut });
  const notes = new Map<string, NoteRecord>();
  const threads = new Map<string, NoteThread>();
  let failPutNote = opts.failPutNote ?? 0, failPutThread = opts.failPutThread ?? 0;
  const io = {
    putNote: async (n: NoteRecord) => { if (failPutNote > 0) { failPutNote--; throw new Error('notes store write failed'); } notes.set(n.note_id, n); },
    putThread: async (t: NoteThread) => { if (failPutThread > 0) { failPutThread--; throw new Error('thread store write failed'); } threads.set(t.thread_id, t); },
    listThreads: async () => [...threads.values()],
  };
  const accept = () => acceptInboundNote({
    wire,
    isAdmitted: async () => true,
    openRatchet: (_from, body) => openDirectNoteStaged(THEM, body, me, peerOf(them), session.io),
    io,
  });
  return { accept, session, notes, threads, wire, me, them };
}

// ── R4 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

test('R4: the note store write FAILS after the open → the session is NOT advanced, and the retry opens the SAME frame (message not lost)', async () => {
  const s = await scenario({ failPutNote: 1 });
  await assert.rejects(() => s.accept(), /notes store write failed/);
  assert.equal(s.session.puts(), 0, 'the session advance was not persisted: the failed store write left it untouched');
  assert.equal(s.notes.size, 0);

  const rec = await s.accept();                                       // the consume loop retries the envelope
  assert.ok(rec, 'the retried frame OPENS (before: receive() returned null and the message was dropped)');
  assert.equal(rec!.body, 'the secret message');
  assert.equal(s.notes.get('note_r4')?.body, 'the secret message');
  assert.equal(s.session.puts(), 1, 'now, and only now, the session advance is persisted');
});

test('R4: the THREAD write fails after the note was stored → still no commit; the retry opens, re-stores idempotently, commits once', async () => {
  const s = await scenario({ failPutThread: 1 });
  await assert.rejects(() => s.accept(), /thread store write failed/);
  assert.equal(s.session.puts(), 0);
  assert.equal(s.notes.size, 1, 'the note itself is already stored (putNote is idempotent on note_id)');
  const rec = await s.accept();
  assert.ok(rec);
  assert.equal(s.notes.size, 1, 'no duplicate note');
  assert.equal(s.threads.size, 1);
  assert.equal(s.session.puts(), 1);
});

test('R4: the session COMMIT itself fails after everything was stored → the session is still un-advanced, so the retry re-opens and commits', async () => {
  const s = await scenario({ failSessionPut: 1 });
  await assert.rejects(() => s.accept(), /session store write failed/);
  assert.equal(s.notes.size, 1, 'the note is stored');
  assert.equal(s.session.puts(), 0, 'the failed commit left the session as it was');
  const rec = await s.accept();
  assert.ok(rec, 'the same frame opens again');
  assert.equal(s.notes.size, 1, 'idempotent: still one note');
  assert.equal(s.session.puts(), 1);
});

test('R4: once a frame has been committed, a REPLAY of it is dropped (not stored twice, not re-advanced)', async () => {
  const s = await scenario();
  assert.ok(await s.accept());
  assert.equal(s.session.puts(), 1);
  assert.equal(await s.accept(), null, 'the replayed frame does not open');
  assert.equal(s.session.puts(), 1);
  assert.equal(s.notes.size, 1);
});

test('R4 compat: an openRatchet that returns a plain string (already committed, the old contract) still works', async () => {
  const s = await scenario();
  const rec = await acceptInboundNote({
    wire: s.wire, isAdmitted: async () => true,
    openRatchet: async () => 'plain string result',
    io: { putNote: async (n) => { s.notes.set(n.note_id, n); }, putThread: async (t) => { s.threads.set(t.thread_id, t); }, listThreads: async () => [] },
  });
  assert.equal(rec?.body, 'plain string result');
});

// ── R2 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

test('R2: a store open for ANOTHER identity, or locked, throws before any session read or write (the inner storage is never touched)', async () => {
  for (const openOwner of ['someone-else', null] as Array<string | null>) {
    const inner = memIO();
    const bound = ownerBoundRatchetIO(ME, () => openOwner, inner.io);
    await assert.rejects(() => bound.read(THEM), /not open for this owner/);
    await assert.rejects(() => bound.put(THEM, {} as RatchetSnapshot, 0), /not open for this owner/);
    assert.deepEqual(inner.log, [], `inner storage untouched (store owner = ${openOwner})`);
  }
  const ok = memIO();
  const bound = ownerBoundRatchetIO(ME, () => ME, ok.io);
  assert.deepEqual(await bound.read(THEM), { state: 'absent' });
  assert.deepEqual(ok.log, [`read:${THEM}`], 'the right owner passes straight through');
});

test('R2: the send policy and the staged open both fail closed against a wrong-owner store, creating nothing', async () => {
  const me = ratchetIdentity(), them = ratchetIdentity();
  const inner = memIO();
  const wrong = ownerBoundRatchetIO(ME, () => 'someone-else', inner.io);
  await assert.rejects(() => chooseWireBody({ body: 'x', peerFingerprint: THEM, canDeposit: true, ownerRatchet: me, peerRatchet: peerOf(them) }, wrong), /not open for this owner/);
  const frame = await sealDirectNote(ME, 'hi', them, peerOf(me), memIO().io);
  await assert.rejects(() => openDirectNoteStaged(THEM, frame!, me, peerOf(them), wrong), /not open for this owner/);
  assert.deepEqual(inner.log, []);
  assert.equal(inner.rows.size, 0, 'no session was created');
});

test('R2 wiring: production send and receive go through ownerBoundRatchetIO; the unbound handle is not reachable from them', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const code = (rel: string) => readFileSync(join(root, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  assert.match(code('lib/messaging/transport.ts'), /ownerBoundRatchetIO\(args\.sender\.fingerprint\)/);
  assert.match(code('lib/sync/live-book-poll.ts'), /openDirectNoteStaged(?:Typed)?\([^)]*ownerBoundRatchetIO\(owner\.fingerprint\)/);
  const users: string[] = [];
  for (const rel of readdirSync(root, { recursive: true }) as string[]) {
    if (!/\.(ts|tsx)$/.test(rel) || /\.test\./.test(rel) || rel.endsWith('lib/messaging/direct-session.ts')) continue;
    if (/\brealRatchetIO\b/.test(code(rel))) users.push(rel);
  }
  assert.deepEqual(users, [], 'nothing outside direct-session.ts may use the unbound realRatchetIO');
});
