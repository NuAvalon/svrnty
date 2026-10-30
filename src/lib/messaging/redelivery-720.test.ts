// src/lib/messaging/redelivery-720.test.ts
// #720 r2 (Flint): at-least-once redelivery of a RATCHET note. The note is stored and its session advance committed, then the ack never
// lands (tab closed mid-poll, an ack request that failed, a lock that ended the cycle). The relay redelivers the same frame. Its message key
// is spent, so the ratchet open fails as a VERDICT ('ratchet-receive-failed', measured below with the real ratchet). Without a check, r2 turns
// that into a 'ratchet-unopenable' record ("couldn't open a message from <contact>") for a note that is already in the inbox. Before r2 it was
// a silent ack (harmless). The note store already makes putNote idempotent on note_id; the ratchet open is not, so the stored note must be
// recognised BEFORE the open. NEG-first: on b250f6d R1 fails.
// Run: npx tsx --test src/lib/messaging/redelivery-720.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { x25519 } from '@noble/curves/ed25519.js';
import { generatePQKeypairBundle, generateKEMKeypair, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import type { RatchetIdentity, RatchetPeer } from '@/lib/crypto/message-ratchet';
import { NOTE_WIRE_TYPE } from './domains';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { sealDirectNote, openDirectNoteStagedTyped } from './direct-session';
import { memIO } from './ratchet-test-io';
import type { NoteRecord, NoteWireV0 } from './types';

async function canonical(name: string) {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fingerprint, publicKey, privateKey, passphrase, kem: uint8ToBase64(pq.kem.publicKey), sig: uint8ToBase64(pq.signing.publicKey) };
}
function ratchetIdent(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });

async function setup() {
  const sender = await canonical('sender');
  const [me, them] = [ratchetIdent(), ratchetIdent()];
  const frame = (await sealDirectNote(sender.fingerprint, 'hello', them, peerOf(me), memIO().io))!;
  const unsigned: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: 'note-r1', thread_id: 'thread-r1', from_fingerprint: sender.fingerprint, sent_at: '2026-10-30T12:00:00.000Z', body: frame, participant_kind: 'human' };
  const wire = await signNoteWire(unsigned, sender.publicKey, sender.privateKey, sender.passphrase, sender.kem, sender.sig);
  const recv = memIO().io; // this device's session store: shared across deliveries
  const notes = new Map<string, NoteRecord>();
  const io = {
    putNote: async (n: NoteRecord) => void notes.set(n.note_id, n),
    putThread: async () => {},
    listThreads: async () => [],
    getNote: async (id: string) => notes.get(id) ?? null,
  };
  const openRatchet = (fromFp: string, body: string) => openDirectNoteStagedTyped(fromFp, body, me, peerOf(them), recv);
  return { wire, io, notes, openRatchet, sender };
}

test('R1 a redelivered ratchet note that is already stored is returned as stored: no drop, no loss record', async () => {
  const { wire, io, notes, openRatchet } = await setup();
  const first = await acceptInboundNote({ wire, isAdmitted: async () => true, openRatchet, io: io as never });
  assert.equal(first?.body, 'hello', 'precondition: first delivery opens, stores and commits');
  assert.equal(notes.size, 1);
  // measured fact behind the bug: the same frame now fails to open as a VERDICT
  const reopen = await openRatchet(wire.from_fingerprint, wire.body);
  assert.deepEqual(reopen, { failed: true, kind: 'verdict', cause: 'ratchet-receive-failed' });

  const reasons: string[] = [];
  const again = await acceptInboundNote({ wire, isAdmitted: async () => true, openRatchet, io: io as never, onDrop: (r) => reasons.push(r) });
  assert.deepEqual(reasons, [], 'a note we already hold is not a drop of any kind');
  assert.equal(again?.note_id, 'note-r1');
  assert.equal(again?.body, 'hello', 'the stored note comes back unchanged');
});

test('R2 control: a stored note with the same id from a DIFFERENT sender does not short-circuit (the open runs; a verdict stays a verdict)', async () => {
  const { wire, io, notes, openRatchet } = await setup();
  notes.set('note-r1', { note_id: 'note-r1', thread_id: 'x', from_fingerprint: 'cc'.repeat(32), body: 'someone else' } as NoteRecord);
  const reasons: string[] = [];
  const garbled = { ...wire };
  const r = await acceptInboundNote({ wire: garbled, isAdmitted: async () => true, openRatchet: async () => ({ failed: true, kind: 'verdict', cause: 'malformed-frame' }), io: io as never, onDrop: (x) => reasons.push(x) });
  assert.equal(r, null);
  assert.deepEqual(reasons, ['ratchet-unopenable']);
  void openRatchet;
});
