// src/lib/messaging/ratchet-send-policy.test.ts
//
// B group 2, commit 4a (Flint #439/#454/#455 acceptance): the SEND-side ratchet policy.
//   R1  gate -> ratchet -> sign -> seal -> POST. A note that cannot be deposited (no verified ML-KEM key) touches NO ratchet state.
//   D1  observed capability: ratchet ONLY to a peer we have already OPENED a ratchet frame from (recvCk !== null). Anyone else gets
//       the plain body (still inside the hybrid outer seal). Never labelled ratcheted.
//   R3  a session row that EXISTS but is unreadable is not "no session": never start a parallel session over it, never overwrite it.
// Real ratchet crypto throughout (TripleRatchet, real X25519 + ML-KEM-1024). The only fake is session STORAGE: an in-memory map that
// logs every read and write, so "nothing stateful happened" is an assertion about the log.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer, RatchetSnapshot } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import type { RatchetSessionRead } from './store';
import {
  chooseWireBody, openDirectNote, sealDirectNote, ratchetCapabilityObserved, isTripleRatchetBody,
  RatchetSessionUnreadableError, type RatchetIO,
} from './direct-session';
import { sendNoteToPeer } from './transport';
import type { NoteRecord } from './types';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });

/** In-memory ratchet session storage that records every call. */
function memIO() {
  const rows = new Map<string, RatchetSessionRead>();
  const log: string[] = [];
  const io: RatchetIO = {
    read: async (fp) => { log.push(`read:${fp}`); return rows.get(fp) ?? { state: 'absent' }; },
    put: async (fp, snapshot: RatchetSnapshot) => { log.push(`put:${fp}`); rows.set(fp, { state: 'ok', snapshot }); },
  };
  return { rows, log, io, puts: () => log.filter((l) => l.startsWith('put:')).length };
}

const ME = 'fp-me', THEM = 'fp-them';

/** Make `me` hold a session with `them` in which `them` has already sent a ratchet frame that `me` OPENED (recvCk set). */
async function observedSession() {
  const me = ratchetIdentity(), them = ratchetIdentity();
  const meIO = memIO(), themIO = memIO();
  const first = await sealDirectNote(ME, 'hello from them', them, peerOf(me), themIO.io);   // them -> me, their first frame
  assert.ok(first);
  assert.equal(await openDirectNote(THEM, first!, me, peerOf(them), meIO.io), 'hello from them');
  return { me, them, meIO, themIO };
}

// ── R1: nothing stateful for a note that cannot be deposited ─────────────────────────────────────────────────────────

test('R1: a note that cannot be deposited (no verified kem) reads, creates and advances NO ratchet state, even toward an observed peer', async () => {
  const { me, them, meIO } = await observedSession();
  const before = { log: meIO.log.length, rows: JSON.stringify([...meIO.rows]) };
  const r = await chooseWireBody({ body: 'plain text', peerFingerprint: THEM, canDeposit: false, ownerRatchet: me, peerRatchet: peerOf(them) }, meIO.io);
  assert.deepEqual(r, { wireBody: 'plain text', ratcheted: false });
  assert.equal(meIO.log.length, before.log, 'no read, no write: the session was not even looked at');
  assert.equal(JSON.stringify([...meIO.rows]), before.rows, 'and the stored session is byte-identical');
});

// ── D1: observed capability ──────────────────────────────────────────────────────────────────────────────────────────

test('D1: a peer with NO session gets the plain body and nothing is created (we do not initiate a ratchet at a peer on a guess)', async () => {
  const me = ratchetIdentity(), them = ratchetIdentity(), s = memIO();
  const r = await chooseWireBody({ body: 'first message', peerFingerprint: THEM, canDeposit: true, ownerRatchet: me, peerRatchet: peerOf(them) }, s.io);
  assert.deepEqual(r, { wireBody: 'first message', ratcheted: false });
  assert.equal(isTripleRatchetBody(r.wireBody), false);
  assert.deepEqual(s.log, [`read:${THEM}`], 'one read, no write');
  assert.equal(s.rows.size, 0, 'no initiator session was created');
});

test('D1: an initiator-only session (we sent, they never answered in kind: recvCk null) is NOT enough: plain body, state untouched', async () => {
  const me = ratchetIdentity(), them = ratchetIdentity(), s = memIO();
  assert.ok(await sealDirectNote(THEM, 'earlier ratchet send', me, peerOf(them), s.io));      // an old session from before this gate
  assert.equal(s.puts(), 1);
  const snap1 = JSON.stringify([...s.rows]);
  const r = await chooseWireBody({ body: 'next', peerFingerprint: THEM, canDeposit: true, ownerRatchet: me, peerRatchet: peerOf(them) }, s.io);
  assert.deepEqual(r, { wireBody: 'next', ratcheted: false });
  assert.equal(s.puts(), 1, 'the session was not advanced');
  assert.equal(JSON.stringify([...s.rows]), snap1);
  assert.equal(await ratchetCapabilityObserved(THEM, s.io), false);
});

test('D1: a peer whose ratchet frame we have OPENED is ratcheted to, and the packet really is readable by them', async () => {
  const { me, them, meIO, themIO } = await observedSession();
  assert.equal(await ratchetCapabilityObserved(THEM, meIO.io), true);
  const before = meIO.puts();
  const r = await chooseWireBody({ body: 'a reply, ratcheted', peerFingerprint: THEM, canDeposit: true, ownerRatchet: me, peerRatchet: peerOf(them) }, meIO.io);
  assert.equal(r.ratcheted, true);
  assert.equal(isTripleRatchetBody(r.wireBody), true);
  assert.notEqual(r.wireBody, 'a reply, ratcheted', 'the plaintext is not on the wire');
  assert.equal(meIO.puts(), before + 1, 'the session advanced and was persisted');
  assert.equal(await openDirectNote(ME, r.wireBody, them, peerOf(me), themIO.io), 'a reply, ratcheted', 'they can open it');
});

// ── R3: an unreadable row is not "no session" ────────────────────────────────────────────────────────────────────────

test('R3: an UNREADABLE session row is never overwritten: seal and open fail closed, the capability check and the policy throw/refuse', async () => {
  const me = ratchetIdentity(), them = ratchetIdentity(), s = memIO();
  s.rows.set(THEM, { state: 'unreadable' });
  const frame = await sealDirectNote(ME, 'a valid frame from them', them, peerOf(me), memIO().io);
  assert.ok(frame);

  assert.equal(await sealDirectNote(THEM, 'x', me, peerOf(them), s.io), null, 'seal: no parallel initiator session over the unreadable row');
  assert.equal(await openDirectNote(THEM, frame!, me, peerOf(them), s.io), null, 'open: no acceptFirst over the unreadable row');
  await assert.rejects(() => ratchetCapabilityObserved(THEM, s.io), RatchetSessionUnreadableError);
  await assert.rejects(() => chooseWireBody({ body: 'x', peerFingerprint: THEM, canDeposit: true, ownerRatchet: me, peerRatchet: peerOf(them) }, s.io), RatchetSessionUnreadableError);
  assert.equal(s.puts(), 0, 'nothing was written');
  assert.deepEqual(s.rows.get(THEM), { state: 'unreadable' }, 'the unreadable row is exactly as it was');
});

test('R3: a readable-but-corrupt snapshot also fails closed: no parallel session, no write', async () => {
  const me = ratchetIdentity(), them = ratchetIdentity(), s = memIO();
  s.rows.set(THEM, { state: 'ok', snapshot: { garbage: true } as unknown as RatchetSnapshot });
  assert.equal(await sealDirectNote(THEM, 'x', me, peerOf(them), s.io), null);
  assert.equal(s.puts(), 0);
});

// ── the real flow: sendNoteToPeer, with the stores injected ──────────────────────────────────────────────────────────

type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };

async function flowArgs(over: { kem: boolean; io: RatchetIO }) {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  const stored: NoteRecord[] = [];
  const fetched: string[] = [];
  const me = ratchetIdentity(), them = ratchetIdentity();
  const call = () => sendNoteToPeer({
    sender: { fingerprint: idOf(sender).fingerprint, participant_kind: 'human' },
    senderPublicKeyArmored: idOf(sender).public_key,
    senderPrivateKeyArmored: sender.secret_material.classicalPrivateKey,
    passphrase: sender.secret_material.classicalKpass,
    senderPqKemPublicKey: idOf(sender).pq_kem_public_key,
    senderPqSigPublicKey: idOf(sender).pq_sig_public_key,
    peerFingerprint: THEM,
    peerPublicKeyArmored: idOf(peer).public_key,
    peerPqKemPublicKey: over.kem ? idOf(peer).pq_kem_public_key : undefined,
    body: 'hello',
    ownerRatchet: me,
    peerRatchet: peerOf(them),
    fetchImpl: (async (url: string) => { fetched.push(String(url)); return new Response('{"ok":true}', { status: 200 }); }) as typeof fetch,
    io: { ratchet: over.io, putNote: async (n: NoteRecord) => { stored.push(n); }, listThreads: async () => [], putThread: async () => {} },
  });
  return { call, stored, fetched, me, them };
}

test('flow R1: sendNoteToPeer to a peer with NO verified kem deposits nothing AND touches no ratchet state, and still records the note as not sent', async () => {
  const s = memIO();
  const f = await flowArgs({ kem: false, io: s.io });
  const r = await f.call();
  assert.equal(r.deposited, false);
  assert.deepEqual(f.fetched, [], 'nothing was POSTed');
  assert.deepEqual(s.log, [], 'the ratchet was not touched at all');
  assert.equal(f.stored.length, 1, 'the local copy is kept (as not-sent)');
});

test('flow D1: a peer not yet observed gets a PLAIN body deposited (one read, no ratchet write, nothing initiated)', async () => {
  const s = memIO();
  const f = await flowArgs({ kem: true, io: s.io });
  const r = await f.call();
  assert.equal(r.deposited, true);
  assert.equal(f.fetched.length, 1);
  assert.deepEqual(s.log, [`read:${THEM}`]);
  assert.equal(s.rows.size, 0);
  assert.equal(f.stored[0].body, 'hello');
});

test('flow D1: a peer observed to send ratchet frames is ratcheted to: deposited, and the session advanced exactly once', async () => {
  const s = memIO();
  const f = await flowArgs({ kem: true, io: s.io });
  // give "me" an observed session with the SAME ratchet identities the flow will use
  const first = await sealDirectNote(ME, 'their first frame', f.them, peerOf(f.me), memIO().io);
  assert.equal(await openDirectNote(THEM, first!, f.me, peerOf(f.them), s.io), 'their first frame');
  const putsBefore = s.puts();
  const r = await f.call();
  assert.equal(r.deposited, true);
  assert.equal(f.fetched.length, 1);
  assert.equal(s.puts(), putsBefore + 1);
});
