// Run: npx tsx --test src/lib/messaging/send-recipient-gate.test.ts
// A note goes only to someone the address book admits as it stands when Send runs, whatever list the screen was showing. The check comes
// first: a refused note touches no ratchet state, signs nothing, stores nothing and posts nothing. Real keys; the fakes are the relay and storage.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { deriveMailboxId } from '../relay/mailbox-auth';
import { NoteSendError, sendNoteToPeer, type SendNoteToPeerArgs } from './transport';
import { memIO } from './ratchet-test-io';
import type { NoteRecord } from './types';
import { NOTES_COPY } from '../../components/notes/notes-copy';
import { sendNoteFromInbox } from '../../components/notes/notes-send';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };

async function flow(admit: unknown) {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  const stored: NoteRecord[] = [];
  const posts: Array<{ mailbox_id: string }> = [];
  const ratchet = memIO();
  const calls: string[] = [];
  const peerFingerprint = idOf(peer).fingerprint;
  const fetchImpl = (async (_u: string, init: RequestInit) => {
    posts.push(JSON.parse(String(init.body)));
    return new Response('{"ok":true}', { status: 200 });
  }) as typeof fetch;
  const call = () => sendNoteToPeer({
    sender: { fingerprint: idOf(sender).fingerprint, participant_kind: 'human' },
    senderPublicKeyArmored: idOf(sender).public_key,
    senderPrivateKeyArmored: sender.secret_material.classicalPrivateKey,
    passphrase: sender.secret_material.classicalKpass,
    senderPqKemPublicKey: idOf(sender).pq_kem_public_key,
    senderPqSigPublicKey: idOf(sender).pq_sig_public_key,
    peerFingerprint,
    peerPublicKeyArmored: idOf(peer).public_key,
    peerPqKemPublicKey: idOf(peer).pq_kem_public_key,
    body: 'hello there',
    ownerRatchet: ratchetIdentity(),
    peerRatchet: peerOf(ratchetIdentity()),
    fetchImpl,
    admit: (typeof admit === 'function' ? (fp: string) => { calls.push(fp); return (admit as (f: string) => boolean)(fp); } : admit) as SendNoteToPeerArgs['admit'],
    io: { ratchet: ratchet.io, putNote: async (n: NoteRecord) => { stored.push(n); }, listThreads: async () => [], putThread: async () => {} },
  });
  return { call, stored, posts, ratchet, calls, peerFingerprint };
}

async function failure(call: () => Promise<unknown>): Promise<NoteSendError> {
  try { await call(); } catch (e) { assert.ok(e instanceof NoteSendError, `expected a NoteSendError, got ${String(e)}`); return e; }
  assert.fail('expected the send to throw');
}

function nothingHappened(f: Awaited<ReturnType<typeof flow>>) {
  assert.equal(f.posts.length, 0, 'nothing was posted');
  assert.equal(f.stored.length, 0, 'no local note was written');
  assert.deepEqual(f.ratchet.log, [], 'no ratchet state was touched');
}

test('control: an admitted contact gets the note, one POST to the mailbox of the fingerprint that was checked', async () => {
  const f = await flow(() => true);
  const r = await f.call();
  assert.equal(r.deposited, true);
  assert.deepEqual(f.calls, [f.peerFingerprint]);
  assert.equal(f.posts.length, 1);
  assert.equal(f.posts[0].mailbox_id, deriveMailboxId(f.peerFingerprint));
  assert.equal(f.stored.length, 1);
});

test('a refused recipient: kind "blocked", and no ratchet, no local note, no POST', async () => {
  const f = await flow(() => false);
  const e = await failure(f.call);
  assert.equal(e.kind, 'blocked');
  nothingHappened(f);
});

test('a missing check sends nothing (fail closed), and says nothing left the device', async () => {
  const f = await flow(undefined);
  const e = await failure(f.call);
  assert.equal(e.kind, 'not-sent');
  nothingHappened(f);
});

test('a check that throws sends nothing', async () => {
  const f = await flow(() => { throw new Error('book unreadable'); });
  const e = await failure(f.call);
  assert.equal(e.kind, 'not-sent');
  nothingHappened(f);
});

async function inboxArgs() {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  return {
    sender: { fingerprint: idOf(sender).fingerprint, publicKeyArmored: idOf(sender).public_key, privateKeyArmored: sender.secret_material.classicalPrivateKey, passphrase: sender.secret_material.classicalKpass, pqKemPublicKey: idOf(sender).pq_kem_public_key, pqSigPublicKey: idOf(sender).pq_sig_public_key, canonical: true },
    peerFingerprint: idOf(peer).fingerprint,
    peerPublicKeyArmored: idOf(peer).public_key,
    peerPqKemPublicKey: idOf(peer).pq_kem_public_key,
    peerPqSigPublicKey: idOf(peer).pq_sig_public_key,
    body: 'hi',
  } as unknown as Parameters<typeof sendNoteFromInbox>[0];
}

test('inbox: a refused recipient comes back as "blocked" with its own line, through the real send path', async () => {
  const r = await sendNoteFromInbox({ ...(await inboxArgs()), loadRecipientGate: async () => () => false });
  assert.deepEqual(r, { ok: false, kind: 'blocked', error: NOTES_COPY.sendBlocked });
});

test('inbox: if the address book cannot be read, nothing is sent and the screen says so', async () => {
  let sends = 0;
  const r = await sendNoteFromInbox({ ...(await inboxArgs()), loadRecipientGate: async () => { throw new Error('locked'); }, send: (async () => { sends++; throw new Error('no'); }) as typeof sendNoteToPeer });
  assert.deepEqual(r, { ok: false, kind: 'not-sent', error: NOTES_COPY.sendFailed });
  assert.equal(sends, 0);
});

test('inbox: a caller with no gate loader sends nothing', async () => {
  let sends = 0;
  const args = { ...(await inboxArgs()), send: (async () => { sends++; throw new Error('no'); }) as typeof sendNoteToPeer };
  const r = await sendNoteFromInbox(args);
  assert.deepEqual(r, { ok: false, kind: 'not-sent', error: NOTES_COPY.sendFailed });
  assert.equal(sends, 0);
});

test('inbox: the book is re-read on every send, and that gate is the one the send uses', async () => {
  const gates: unknown[] = [];
  let loads = 0;
  const args = await inboxArgs();
  const send = (async (a: SendNoteToPeerArgs) => { gates.push(a.admit); return { note_id: 'n', thread_id: 't', deposited: true }; }) as typeof sendNoteToPeer;
  const made: unknown[] = [];
  const loadRecipientGate = async () => { loads++; const g = () => true; made.push(g); return g; };
  await sendNoteFromInbox({ ...args, send, loadRecipientGate });
  await sendNoteFromInbox({ ...args, send, loadRecipientGate });
  assert.equal(loads, 2);
  assert.deepEqual(gates, made);
});

test('the blocked line is honest: it keeps the draft and promises nothing', () => {
  assert.equal(NOTES_COPY.sendBlocked, 'Not sent. This contact is blocked or removed. Your message is still in the box.');
});
