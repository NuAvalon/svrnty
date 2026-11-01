// src/lib/messaging/ratchet-desync-720.test.ts
// #720 T2 end to end with the REAL TripleRatchet and the REAL acceptInboundNote: a contact whose session no longer agrees with ours (they started a NEW
// session, which is exactly what a peer-side reset looks like) produces a DESYNC: onDrop 'ratchet-desync', nothing stored, OUR session untouched.
// Run: npx tsx --test src/lib/messaging/ratchet-desync-720.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { memIO } from './ratchet-test-io';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { NOTE_WIRE_TYPE } from './domains';
import { sealDirectNote, openDirectNoteStagedTyped } from './direct-session';
import type { NoteRecord, NoteThread, NoteWireV0 } from './types';

const ident = (): RatchetIdentity => {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
};
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const ME = 'fp-me', THEM = 'fp-them';

async function world() {
  const [me, them] = [ident(), ident()];
  const sender = await mintHeadlessAgent({ throwaway: true });
  const id = sender.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  const myIO = memIO();
  const notes = new Map<string, NoteRecord>(), threads = new Map<string, NoteThread>();
  const io = {
    putNote: async (n: NoteRecord) => { notes.set(n.note_id, n); }, putThread: async (t: NoteThread) => { threads.set(t.thread_id, t); },
    listThreads: async () => [...threads.values()], getNote: async (nid: string) => notes.get(nid) ?? null,
  };
  const wireFor = (note_id: string, body: string): Promise<NoteWireV0> =>
    signNoteWire({ type: NOTE_WIRE_TYPE, note_id, thread_id: 'thr', from_fingerprint: id.fingerprint, sent_at: new Date().toISOString(), body, participant_kind: 'human' },
      id.public_key, sender.secret_material.classicalPrivateKey, sender.secret_material.classicalKpass, id.pq_kem_public_key, id.pq_sig_public_key);
  const accept = async (wire: NoteWireV0) => {
    const reasons: string[] = [];
    const r = await acceptInboundNote({ wire, isAdmitted: async () => true, io: io as never, onDrop: (x) => reasons.push(x),
      openRatchet: (_f, body) => openDirectNoteStagedTyped(THEM, body, me, peerOf(them), myIO.io) });
    return { r, reasons };
  };
  return { me, them, myIO, notes, wireFor, accept };
}

test('D1 a peer that started a NEW session (their reset) while ours is established => DESYNC: nothing stored, our session row byte-identical, held class', async () => {
  const w = await world();
  const theirOld = memIO();
  const first = (await sealDirectNote(ME, 'before the reset', w.them, peerOf(w.me), theirOld.io))!;
  const ok = await w.accept(await w.wireFor('n-first', first));
  assert.ok(ok.r, 'setup: the first frame opens and is stored'); assert.deepEqual(ok.reasons, []);
  const before = JSON.stringify(w.myIO.rows.get(THEM));
  const theirNew = memIO();                                   // THEM starts over: a brand-new first frame under a brand-new session
  const afterReset = (await sealDirectNote(ME, 'after their reset', w.them, peerOf(w.me), theirNew.io))!;
  const bad = await w.accept(await w.wireFor('n-after', afterReset));
  assert.equal(bad.r, null);
  assert.deepEqual(bad.reasons, ['ratchet-desync']);
  assert.equal(w.notes.has('n-after'), false, 'nothing was stored for the unopened frame');
  assert.equal(JSON.stringify(w.myIO.rows.get(THEM)), before, 'OUR session is untouched (T1)');
});

test('D2 a malformed ratchet body stays a VERDICT (not held): the desync class is only for a well-formed frame from an authenticated contact whose session disagrees', async () => {
  const w = await world();
  const bad = await w.accept(await w.wireFor('n-bad', JSON.stringify({ type: 'svrnty-tr-v1', packet: { not: 'a ratchet packet' } })));
  assert.equal(bad.r, null);
  assert.deepEqual(bad.reasons, ['ratchet-unopenable']);
});
