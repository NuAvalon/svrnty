// src/lib/messaging/thread-activity-send.test.ts
// Chat-list order on the SEND side: our own send is stamped "now", and it must not move an existing thread's last_activity_at backwards
// (a received note stamped a little ahead of our clock) or leave a pinned far-future value in place. Real keys and sealing; the only
// fakes are the relay (fetchImpl) and the storage (io).
// Run: npx tsx --test src/lib/messaging/thread-activity-send.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { sendNoteToPeer } from './transport';
import { ACTIVITY_FUTURE_SLACK_MS } from './thread-activity';
import { memIO } from './ratchet-test-io';
import type { NoteRecord, NoteThread } from './types';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };

async function flow() {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  const me = ratchetIdentity(), them = ratchetIdentity();
  const ratchet = memIO().io;
  let threads: NoteThread[] = [];
  const puts: NoteThread[] = [];
  const okFetch = (async () => new Response('{"ok":true}', { status: 200 })) as unknown as typeof fetch;
  // A send without a threadId starts a NEW thread, so the second send of each test names the first one's thread.
  const send = (threadId?: string) => sendNoteToPeer({
    sender: { fingerprint: idOf(sender).fingerprint, participant_kind: 'human' },
    senderPublicKeyArmored: idOf(sender).public_key,
    senderPrivateKeyArmored: sender.secret_material.classicalPrivateKey,
    passphrase: sender.secret_material.classicalKpass,
    senderPqKemPublicKey: idOf(sender).pq_kem_public_key,
    senderPqSigPublicKey: idOf(sender).pq_sig_public_key,
    peerFingerprint: 'fp-them',
    peerPublicKeyArmored: idOf(peer).public_key,
    peerPqKemPublicKey: idOf(peer).pq_kem_public_key,
    body: 'hello there',
    threadId,
    ownerRatchet: me,
    peerRatchet: peerOf(them),
    fetchImpl: okFetch,
    io: {
      ratchet,
      putNote: async (_n: NoteRecord) => {},
      listThreads: async () => threads,
      putThread: async (t: NoteThread) => { puts.push(t); },
    },
  });
  return { send, puts, setThreads: (t: NoteThread[]) => { threads = t; } };
}

test('S1 NEG: sending into a thread whose activity is slightly ahead of our clock does not move it back', async () => {
  const f = await flow();
  await f.send(); // creates the thread
  const created = f.puts[0];
  const seed = new Date(Date.now() + 2 * 60_000).toISOString(); // inside the slack, newer than "now"
  f.setThreads([{ ...created, last_activity_at: seed }]);
  await f.send(created.thread_id);
  assert.equal(f.puts[1].thread_id, created.thread_id, 'the existing thread was found, not a new one');
  assert.equal(f.puts[1].last_activity_at, seed);
});

test('S2 NEG: sending into a thread already pinned in 2099 heals it to now+slack instead of leaving it', async () => {
  const f = await flow();
  await f.send();
  f.setThreads([{ ...f.puts[0], last_activity_at: '2099-01-01T00:00:00.000Z' }]);
  const before = Date.now();
  await f.send(f.puts[0].thread_id);
  assert.equal(f.puts[1].thread_id, f.puts[0].thread_id, 'the existing thread was found, not a new one');
  const got = Date.parse(f.puts[1].last_activity_at);
  assert.ok(got <= Date.now() + ACTIVITY_FUTURE_SLACK_MS + 1000, 'no longer in 2099');
  assert.ok(got >= before + ACTIVITY_FUTURE_SLACK_MS - 5000, 'clamped at the ceiling, not dropped to our send time');
});
