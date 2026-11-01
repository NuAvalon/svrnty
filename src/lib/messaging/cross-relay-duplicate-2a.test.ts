// src/lib/messaging/cross-relay-duplicate-2a.test.ts
// Failover T2 phase 2a (Flint #2639): the SAME triple-ratchet blob delivered via relay A and then relay B must be ONE stored note with ZERO drops
// (so no dead-letter row and no #731 "couldn't be opened" line for a message the user already has). note_id is on the OUTER signed wire, readable
// after the stateless seal opens, so the check runs on the note, not on the envelope id (which is relay-scoped). Real acceptInboundNote + real ratchet.
// Run: npx tsx --test src/lib/messaging/cross-relay-duplicate-2a.test.ts
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

/** Flip one base64 char inside the frame's ciphertext: still a well-formed TR frame, but it will not open. */
const tamperCt = (body: string): string => {
  const i = body.indexOf('"ct":"') + 12;
  return body.slice(0, i) + (body[i] === 'A' ? 'B' : 'A') + body.slice(i + 1);
};
const unsignedOf = (w: NoteWireV0, note_id: string, body: string): NoteWireV0 => ({ type: NOTE_WIRE_TYPE, note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint, sent_at: w.sent_at, body, participant_kind: 'human' });

async function setup() {
  const sender = await canonical('sender');
  const [me, them] = [ratchetIdent(), ratchetIdent()];
  const sio = memIO().io;
  const frame = (await sealDirectNote(sender.fingerprint, 'hello', them, peerOf(me), sio))!;
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
  return { wire, io, notes, openRatchet, sender, frame, them, me, recv, sio };
}


test('X1 relay A then relay B deliver the same TR blob: one stored note, zero drops, the stored body unchanged', async () => {
  const { wire, io, notes, openRatchet } = await setup();
  const drops: string[] = [];
  const viaA = await acceptInboundNote({ wire, isAdmitted: async () => true, openRatchet, io: io as never, onDrop: (r) => drops.push('A:' + r) });
  assert.equal(viaA?.body, 'hello', 'precondition: the first copy opens, stores and commits');
  const viaB = await acceptInboundNote({ wire, isAdmitted: async () => true, openRatchet, io: io as never, onDrop: (r) => drops.push('B:' + r) });
  assert.equal(viaB?.note_id, 'note-r1');
  assert.equal(viaB?.body, 'hello');
  assert.equal(notes.size, 1);
  assert.deepEqual(drops, [], 'no drop of any kind, so no dead-letter row can be written');
});

test('X2 frame N via relay A and frame N+1 via relay B both open (Flint #2635 NEG): one session, advanced once per frame, nothing lost', async () => {
  const { wire, io, notes, openRatchet, sender, them, me, sio } = await setup();
  const first = await acceptInboundNote({ wire, isAdmitted: async () => true, openRatchet, io: io as never });
  assert.equal(first?.body, 'hello');
  const frame2 = (await sealDirectNote(sender.fingerprint, 'second', them, peerOf(me), sio))!;
  const wire2 = await signNoteWire({ ...unsignedOf(wire, 'note-r2', frame2) }, sender.publicKey, sender.privateKey, sender.passphrase, sender.kem, sender.sig);
  const drops: string[] = [];
  const second = await acceptInboundNote({ wire: wire2, isAdmitted: async () => true, openRatchet, io: io as never, onDrop: (r) => drops.push(r) });
  assert.equal(second?.body, 'second', 'the next frame (the other relay) opens on the same session');
  assert.equal(notes.size, 2);
  assert.deepEqual(drops, []);
});

test('X3 a DIFFERENT, broken frame under the SAME sender\'s stored note_id is answered "stored": current behaviour, pinned, not endorsed (authenticated, masks only its own frame)', async () => {
  const { wire, io, notes, openRatchet, sender } = await setup();
  await acceptInboundNote({ wire, isAdmitted: async () => true, openRatchet, io: io as never });
  const broken = await signNoteWire({ ...unsignedOf(wire, 'note-r1', tamperCt(wire.body)) }, sender.publicKey, sender.privateKey, sender.passphrase, sender.kem, sender.sig);
  const drops: string[] = [];
  const r = await acceptInboundNote({ wire: broken, isAdmitted: async () => true, openRatchet, io: io as never, onDrop: (x) => drops.push(x) });
  assert.equal(r?.body, 'hello', 'the earlier stored note comes back; the broken frame is not reported as a loss');
  assert.deepEqual(drops, []);
  assert.equal(notes.size, 1);
});
