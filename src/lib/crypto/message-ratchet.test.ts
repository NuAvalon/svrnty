// src/lib/crypto/message-ratchet.test.ts
// ADVERSARIAL refutation for the hybrid triple ratchet (Phase 3.3 candidate).
// Each named test refutes a property — "an adversary who [X] CANNOT [Y]" —
// or pins an honest claim boundary the construction does NOT provide.
// Run: npx tsx --test src/lib/crypto/message-ratchet.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { generateKEMKeypair, base64ToUint8, uint8ToBase64 } from './pq.js';
import {
  TripleRatchet,
  mixInitialHandshake,
  mixRatchetStep,
  symmetricRatchet,
  MAX_SKIP,
  type RatchetIdentity,
  type RatchetPacket,
  type RatchetPeer,
} from './message-ratchet.js';

function identity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const x25519Pub = x25519.getPublicKey(x25519Sec);
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub, mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}

function peerOf(id: RatchetIdentity): RatchetPeer {
  return { x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub };
}

function flip(b: Uint8Array): Uint8Array {
  const c = new Uint8Array(b);
  c[0] ^= 0x01;
  return c;
}

function tamperB64(b64: string): string {
  const bytes = base64ToUint8(b64);
  bytes[0] ^= 0x01;
  return uint8ToBase64(bytes);
}

async function pair() {
  const aliceId = identity();
  const bobId = identity();
  const alice = TripleRatchet.initiate(aliceId, peerOf(bobId));
  return { aliceId, bobId, alice };
}

test('hybrid mix: flipping the DH leg or the KEM leg changes root and chain', () => {
  const root = new Uint8Array(32).fill(0x11);
  const ssDh = new Uint8Array(32).fill(0x22);
  const ssKem = new Uint8Array(32).fill(0x33);
  const base = mixRatchetStep(root, ssDh, ssKem);
  const again = mixRatchetStep(root, ssDh, ssKem);
  assert.equal(bytesToHex(base.root), bytesToHex(again.root));
  assert.notEqual(bytesToHex(base.root), bytesToHex(base.chain));

  const noKem = mixRatchetStep(root, ssDh, flip(ssKem));
  const noDh = mixRatchetStep(root, flip(ssDh), ssKem);
  assert.notEqual(bytesToHex(base.root), bytesToHex(noKem.root), 'KEM leg is inside the root');
  assert.notEqual(bytesToHex(base.chain), bytesToHex(noKem.chain), 'KEM leg is inside the chain');
  assert.notEqual(bytesToHex(base.root), bytesToHex(noDh.root), 'DH leg is inside the root');
  assert.notEqual(bytesToHex(base.chain), bytesToHex(noDh.chain), 'DH leg is inside the chain');

  const ssStatic = new Uint8Array(32).fill(0x44);
  const ssEph = new Uint8Array(32).fill(0x55);
  const init = mixInitialHandshake(ssStatic, ssEph, ssKem);
  assert.notEqual(bytesToHex(init.root), bytesToHex(mixInitialHandshake(flip(ssStatic), ssEph, ssKem).root));
  assert.notEqual(bytesToHex(init.root), bytesToHex(mixInitialHandshake(ssStatic, flip(ssEph), ssKem).root));
  assert.notEqual(bytesToHex(init.chain), bytesToHex(mixInitialHandshake(ssStatic, ssEph, flip(ssKem)).chain));

  const step = symmetricRatchet(root);
  const step2 = symmetricRatchet(step.ck);
  assert.notEqual(bytesToHex(step.mk), bytesToHex(step2.mk));
  assert.notEqual(bytesToHex(step.ck), bytesToHex(step.mk));
});

test('roundtrip: same-direction follow-ups and a reply both open', async () => {
  const { aliceId, bobId, alice } = await pair();
  const m0 = await alice.send('hello');
  const m1 = await alice.send('hello again');
  assert.equal(m0.header.n, 0);
  assert.equal(m1.header.n, 1);
  assert.equal(m0.header.dh, m1.header.dh, 'same direction repeats the ratchet header');
  assert.equal(m0.header.kemCt, m1.header.kemCt);

  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), m0);
  assert.ok(opened);
  assert.equal(opened.plaintext, 'hello');
  assert.equal(await opened.session.receive(m1), 'hello again');

  const reply = await opened.session.send('the strong 64-hex — meet me at the barzakh 🌀');
  assert.notEqual(reply.header.dh, m0.header.dh, 'a reply is a new epoch');
  assert.equal(await alice.receive(reply), 'the strong 64-hex — meet me at the barzakh 🌀');

  const after = await alice.send('after the turn');
  assert.notEqual(after.header.dh, m0.header.dh);
  assert.equal(await opened.session.receive(after), 'after the turn');
  assert.equal(await opened.session.receive(await alice.send('and once more')), 'and once more');
});

test('out of order within the skip window, then a replay is rejected', async () => {
  const { aliceId, bobId, alice } = await pair();
  const packets: RatchetPacket[] = [];
  for (const text of ['a', 'b', 'c']) packets.push(await alice.send(text));

  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), packets[2]!);
  assert.equal(opened?.plaintext, 'c');
  assert.equal(await opened!.session.receive(packets[0]!), 'a');
  assert.equal(await opened!.session.receive(packets[1]!), 'b');
  assert.equal(await opened!.session.receive(packets[0]!), null, 'used message key is gone');
  assert.equal(await opened!.session.receive(packets[2]!), null);
});

test('over-skip fails closed and does not burn the chain', async () => {
  const { aliceId, bobId, alice } = await pair();
  const first = await alice.send('keep');
  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), first);
  assert.ok(opened);

  const skipped: RatchetPacket[] = [];
  for (let i = 0; i < MAX_SKIP + 1; i++) skipped.push(await alice.send(`gap-${i}`));
  const tooFar = await alice.send('too far');
  // nr is 1, so n = MAX_SKIP+2 is a gap of MAX_SKIP+1.
  assert.equal(tooFar.header.n, MAX_SKIP + 2);

  assert.equal(await opened.session.receive(tooFar), null);
  // The refused packet must not have advanced the chain: the next real index still opens.
  assert.equal(await opened.session.receive(skipped[0]!), 'gap-0');
});

test('(FS) a session that already opened a message cannot open it again', async () => {
  const { aliceId, bobId, alice } = await pair();
  const m0 = await alice.send('past');
  const m1 = await alice.send('next');
  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), m0);
  assert.ok(opened);

  // A clone taken BEFORE the next receive still holds the chain key, so it CAN
  // derive the next message. That is the chain key doing its job, not an FS miss.
  const before = opened.session.clone();
  assert.equal(await before.receive(m1), 'next');

  assert.equal(await opened.session.receive(m1), 'next');
  const after = opened.session.clone();
  assert.equal(await after.receive(m0), null, 'post-decrypt state has no past message key');
  assert.equal(await after.receive(m1), null, 'the key just used was deleted');
  assert.equal(await opened.session.receive(m0), null);
});

test('(PCS) a snapshot taken before our send cannot read the peer reply to that send', async () => {
  const { aliceId, bobId, alice } = await pair();
  const m0 = await alice.send('setup');
  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), m0);
  assert.ok(opened);
  const bob = opened.session;

  // Snapshot Bob before he has ever sent. His first send mints the ephemeral
  // X25519 + ML-KEM the next inbound message will be addressed to.
  const seized = bob.clone();

  // A receiver snapshot still opens an inbound ratchet: that message is
  // addressed to keys the snapshot already holds. Healing is not "any snapshot
  // goes blind." It is the compromised party's own fresh send.
  const aliceSnap = alice.clone();
  const inbound = await bob.send('inbound to keys Alice already has');
  assert.equal(await aliceSnap.receive(inbound), 'inbound to keys Alice already has');
  assert.equal(await alice.receive(inbound), 'inbound to keys Alice already has');

  const follow = await alice.send('addressed to the fresh kem');
  assert.equal(await bob.receive(follow), 'addressed to the fresh kem');
  assert.equal(
    await seized.receive(follow),
    null,
    'snapshot never generated the ephemeral the follow-up was encapsulated to',
  );
});

test('tampered KEM ciphertext or DH pub returns null and leaves the session usable', async () => {
  const { aliceId, bobId, alice } = await pair();
  const good = await alice.send('intact');
  const badCt = { ...good, header: { ...good.header, kemCt: tamperB64(good.header.kemCt) } };
  assert.equal(await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), badCt), null);
  const badDh = { ...good, header: { ...good.header, dh: tamperB64(good.header.dh) } };
  assert.equal(await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), badDh), null);

  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), good);
  assert.equal(opened?.plaintext, 'intact');

  const second = await alice.send('still here');
  const flipped = { ...second, ct: tamperB64(second.ct) };
  assert.equal(await opened!.session.receive(flipped), null);
  assert.equal(await opened!.session.receive(second), 'still here');

  const reply = await opened!.session.send('turn');
  const evilReply = { ...reply, header: { ...reply.header, kemCt: tamperB64(reply.header.kemCt) } };
  assert.equal(await alice.receive(evilReply), null);
  assert.equal(await alice.receive(reply), 'turn');
});

test('Mallory init does not open when Bob expects Alice', async () => {
  const { bobId } = await pair();
  const aliceId = identity();
  const mallory = identity();
  const forged = TripleRatchet.initiate(mallory, peerOf(bobId));
  const pkt = await forged.send('I am Alice');
  assert.equal(await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), pkt), null);

  const real = TripleRatchet.initiate(aliceId, peerOf(bobId));
  const ok = await real.send('actually Alice');
  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), ok);
  assert.equal(opened?.plaintext, 'actually Alice');
});

test('CLAIM BOUNDARY: recipient identity keys re-open the initial flight only', async () => {
  const { aliceId, bobId, alice } = await pair();
  assert.equal(alice.holdsContiguous(aliceId.x25519Sec), false);
  assert.equal(alice.holdsContiguous(aliceId.mlkem1024Sec), false);

  const first = await alice.send('epoch-zero');
  // The sender's own identity secrets are not the recipient's opening keys.
  assert.equal(await TripleRatchet.acceptFirst(aliceId, peerOf(bobId), first), null);

  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), first);
  assert.equal(opened?.plaintext, 'epoch-zero');
  assert.equal(opened!.session.holdsContiguous(bobId.x25519Sec), false);
  assert.equal(opened!.session.holdsContiguous(bobId.mlkem1024Sec), false);
  assert.equal(await opened!.session.receive(first), null, 'the session deleted the message key');

  // No one-time prekey: a fresh accept with the long-term secrets recomputes epoch zero.
  const again = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), first);
  assert.equal(again?.plaintext, 'epoch-zero');

  const reply = await opened!.session.send('epoch-one');
  assert.equal(await alice.receive(reply), 'epoch-one');
  // Identity secrets do not decapsulate a ciphertext aimed at the ephemeral KEM key.
  assert.equal(await TripleRatchet.acceptFirst(aliceId, peerOf(bobId), reply), null);
  assert.equal(await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), reply), null);
});

test('a skipped tail of the previous epoch still opens after the turn', async () => {
  const { aliceId, bobId, alice } = await pair();
  const p0 = await alice.send('0');
  const p1 = await alice.send('1');
  const p2 = await alice.send('2');
  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), p0);
  assert.ok(opened);
  const bob = opened.session;

  const reply = await bob.send('your turn');
  assert.equal(await alice.receive(reply), 'your turn');
  const next = await alice.send('new epoch');
  assert.equal(next.header.pn, 3, 'previous sending chain length rides in pn');
  assert.equal(await bob.receive(next), 'new epoch');
  assert.equal(await bob.receive(p1), '1');
  assert.equal(await bob.receive(p2), '2');
  assert.equal(await bob.receive(p1), null);
});

test('garbage packets return null; bad identity lengths throw', async () => {
  const { aliceId, bobId, alice } = await pair();
  const good = await alice.send('x');
  const opened = await TripleRatchet.acceptFirst(bobId, peerOf(aliceId), good);
  assert.ok(opened);
  assert.equal(await opened.session.receive(null as unknown as RatchetPacket), null);
  assert.equal(await opened.session.receive({} as RatchetPacket), null);
  assert.equal(
    await opened.session.receive({ ...good, header: { ...good.header, v: 2 as 1 } }),
    null,
  );

  const bobPeer = peerOf(bobId);
  assert.throws(() =>
    TripleRatchet.initiate(
      { ...aliceId, x25519Sec: new Uint8Array(16) },
      bobPeer,
    ),
  );
  assert.throws(() =>
    TripleRatchet.initiate(aliceId, { ...bobPeer, mlkem1024Pub: new Uint8Array(32) }),
  );
});
