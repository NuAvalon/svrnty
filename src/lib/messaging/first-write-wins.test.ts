// src/lib/messaging/first-write-wins.test.ts
// FIRST WRITE WINS (Archie #2653, Flint #2650/#2655): a contact may REDELIVER a note they sent (identical content), never REWRITE it. Real
// acceptInboundNote, real signatures, and a real triple-ratchet frame for the session cases.
// Run: npx tsx --test src/lib/messaging/first-write-wins.test.ts
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
  return { wire, io, notes, openRatchet, sender, them, me, sio };
}


const unsignedOf = (w: NoteWireV0, over: Partial<NoteWireV0>): NoteWireV0 => ({ type: NOTE_WIRE_TYPE, note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint, sent_at: w.sent_at, body: w.body, participant_kind: 'human', ...over });
const resign = (s: Awaited<ReturnType<typeof canonical>>, u: NoteWireV0) => signNoteWire(u, s.publicKey, s.privateKey, s.passphrase, s.kem, s.sig);
const ok = async () => true;

async function plain() {
  const sender = await canonical('sender');
  const notes = new Map<string, NoteRecord>();
  const io = { putNote: async (n: NoteRecord) => void notes.set(n.note_id, n), putThread: async () => {}, listThreads: async () => [], getNote: async (id: string) => notes.get(id) ?? null };
  const base: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: sender.fingerprint, sent_at: '2026-10-30T12:00:00.000Z', body: 'what I really said', participant_kind: 'human' };
  return { sender, notes, io, base, wireWith: (over: Partial<NoteWireV0>) => resign(sender, unsignedOf(base, over)) };
}

test('W1 NEG: the same sender sends a DIFFERENT body under a stored note_id => the stored row is unchanged, the stored note comes back, the refusal is counted once, no drop', async () => {
  const { notes, io, wireWith } = await plain();
  assert.equal((await acceptInboundNote({ wire: await wireWith({}), isAdmitted: ok, io: io as never }))?.body, 'what I really said');
  let refused = 0;
  const drops: string[] = [];
  const r = await acceptInboundNote({ wire: await wireWith({ body: 'EDITED later' }), isAdmitted: ok, io: io as never, onRewriteRefused: () => refused++, onDrop: (x) => drops.push(x) });
  assert.equal(r?.body, 'what I really said', 'the first write wins');
  assert.equal(notes.get('n1')?.body, 'what I really said');
  assert.equal(notes.size, 1);
  assert.equal(refused, 1);
  assert.deepEqual(drops, []);
});

test('W2 control: a byte-identical redelivery is the same row, no refusal, no drop', async () => {
  const { notes, io, wireWith } = await plain();
  await acceptInboundNote({ wire: await wireWith({}), isAdmitted: ok, io: io as never });
  let refused = 0;
  const r = await acceptInboundNote({ wire: await wireWith({}), isAdmitted: ok, io: io as never, onRewriteRefused: () => refused++ });
  assert.equal(r?.body, 'what I really said');
  assert.equal(refused, 0);
  assert.equal(notes.size, 1);
});

test('W3 NEG: moving the stored note to another thread, or re-dating it, is a rewrite too', async () => {
  const { notes, io, wireWith } = await plain();
  await acceptInboundNote({ wire: await wireWith({}), isAdmitted: ok, io: io as never });
  let refused = 0;
  await acceptInboundNote({ wire: await wireWith({ thread_id: 'other-thread' }), isAdmitted: ok, io: io as never, onRewriteRefused: () => refused++ });
  await acceptInboundNote({ wire: await wireWith({ sent_at: '2026-10-31T01:00:00.000Z' }), isAdmitted: ok, io: io as never, onRewriteRefused: () => refused++ });
  assert.equal(refused, 2);
  assert.equal(notes.get('n1')?.thread_id, 't1');
  assert.equal(notes.get('n1')?.sent_at, '2026-10-30T12:00:00.000Z');
});

test('W4 a DIFFERENT sender reusing the id keeps the existing behaviour (refused as a drop-less null, never counted as a rewrite)', async () => {
  const { notes, io } = await plain();
  const other = await canonical('other');
  notes.set('n1', { note_id: 'n1', thread_id: 't1', direction: 'inbound', from_fingerprint: 'cc'.repeat(32), body: 'someone else' } as NoteRecord);
  let refused = 0;
  const w = await resign(other, { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: other.fingerprint, sent_at: '2026-10-30T12:00:00.000Z', body: 'mine', participant_kind: 'human' });
  assert.equal(await acceptInboundNote({ wire: w, isAdmitted: ok, io: io as never, onRewriteRefused: () => refused++ }), null);
  assert.equal(refused, 0);
  assert.equal(notes.get('n1')?.body, 'someone else');
});

test('W5 (Flint #2655) a VALID new ratchet frame that OPENS under a reused note_id is refused, but its ratchet advance is COMMITTED and the lock released: the next ordinary frame opens on the same session', async () => {
  const { wire, io, notes, openRatchet, sender, them, me, sio } = await setup();
  assert.equal((await acceptInboundNote({ wire, isAdmitted: ok, openRatchet, io: io as never }))?.body, 'hello');
  const frame2 = (await sealDirectNote(sender.fingerprint, 'REWRITTEN history', them, peerOf(me), sio))!;
  const rewrite = await resign(sender, unsignedOf(wire, { body: frame2 }));
  let commits = 0;
  let releases = 0;
  const spying: typeof openRatchet = async (fp, body) => {
    const o = await openRatchet(fp, body);
    if (o && typeof o === 'object' && 'commit' in o) {
      const { commit, release } = o;
      return { ...o, commit: async () => { commits++; return commit(); }, release: () => { releases++; release(); } };
    }
    return o;
  };
  let refused = 0;
  const r = await acceptInboundNote({ wire: rewrite, isAdmitted: ok, openRatchet: spying, io: io as never, onRewriteRefused: () => refused++ });
  assert.equal(r?.body, 'hello', 'the original comes back');
  assert.equal(notes.get('note-r1')?.body, 'hello', 'the stored row is untouched');
  assert.deepEqual([refused, commits], [1, 1], 'refused once, the advance committed once');
  assert.ok(releases >= 1, 'the per-peer lock was released');
  const frame3 = (await sealDirectNote(sender.fingerprint, 'third', them, peerOf(me), sio))!;
  const next = await acceptInboundNote({ wire: await resign(sender, unsignedOf(wire, { note_id: 'note-r3', body: frame3 })), isAdmitted: ok, openRatchet, io: io as never });
  assert.equal(next?.body, 'third', 'NEG 1: the sender\'s NEXT ordinary frame opens on the same session (no desync)');
  assert.equal(notes.size, 2);
});

test('W6 the R4 retry still works: a frame whose stored note exists but whose ratchet commit failed re-opens, finds IDENTICAL content, and commits', async () => {
  const { wire, io, notes } = await setup();
  let attempt = 0;
  let commits = 0;
  const openRatchet = async () => ({ plaintext: 'hello', commit: async () => { if (attempt++ === 0) throw new Error('disk full'); commits++; }, release: () => {} }) as never;
  await assert.rejects(acceptInboundNote({ wire, isAdmitted: ok, openRatchet, io: io as never }), /disk full/);
  assert.equal(notes.size, 1, 'the note was stored before the commit failed');
  let refused = 0;
  const r = await acceptInboundNote({ wire, isAdmitted: ok, openRatchet, io: io as never, onRewriteRefused: () => refused++ });
  assert.equal(r?.body, 'hello');
  assert.deepEqual([refused, commits], [0, 1], 'not a rewrite; the advance is committed on the retry');
});

test('W7 static: the PWA poll wires the refusal counter, and the counter module keeps only a number (no id, sender or text)', async () => {
  const { readFileSync } = await import('node:fs');
  const poll = readFileSync(new URL('../sync/live-book-poll.ts', import.meta.url), 'utf8');
  assert.match(poll, /onRewriteRefused: noteRewriteRefused,/);
  const mod = readFileSync(new URL('./rewrite-refused.ts', import.meta.url), 'utf8');
  assert.match(mod, /export function noteRewriteRefused\(\): void \{/, 'takes no argument, so nothing identifying can be passed');
});
