// src/lib/messaging/ratchet-adopt-720.test.ts
//
// #720 R5 + R6 (Flint reset-semantics v1): the RECEIVING side of a reset. When the peer resets and sends a NEW first frame while we still hold the old
// session, `session.receive` fails (desync). The opener may then try `acceptFirst`, but only if the caller's policy says so (replay guard + tie-break),
// and only a genuine FIRST frame can ever replace a session. Real ratchet crypto (TripleRatchet); the only fake is session STORAGE (memIO).
//   N-R5a  a REPLAYED older first frame does NOT replace the session (policy); N-R5b a fresh one does, and both sides converge on the new session.
//   N-R5d  only a frame that carries the handshake can replace: a REPLAYED frame of the old, confirmed session stays a held desync even when the policy says yes.
//   N-R5f  a later frame of the peer's new session also heals when the first was lost (the initiator keeps the handshake header until it hears back).
//   N-R5e  without a policy (every existing caller) nothing changes: a desync is a desync and the stored row is untouched.
//   N-R6   simultaneous resets: the LOWER fingerprint's initiation wins, deterministically, while our session is unconfirmed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { openDirectNoteStagedTyped, sealDirectNote, type RatchetIO } from './direct-session';
import { FUTURE_SLACK_MS, mayAdoptFirstFrame, RELAY_WINDOW_MS, type AdoptFacts } from './session-adopt-policy';
import { memIO } from './ratchet-test-io';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });

const ME = 'fp-me', ALICE = 'fp-alice';

/** Me holds a CONFIRMED session with Alice (she sent, I opened). Then Alice resets and sends a NEW first frame. */
async function aliceResets() {
  const me = ratchetIdentity(), alice = ratchetIdentity();
  const meIO = memIO(), aliceOld = memIO(), aliceNew = memIO();
  const f1 = await sealDirectNote(ME, 'before the reset', alice, peerOf(me), aliceOld.io);
  const s1 = await openDirectNoteStagedTyped(ALICE, f1!, me, peerOf(alice), meIO.io);
  assert.ok(!('failed' in s1)); await (s1 as { commit: () => Promise<void> }).commit();
  const f2 = await sealDirectNote(ME, 'after the reset', alice, peerOf(me), aliceNew.io); // alice has no row in aliceNew: a NEW first frame
  const f3 = await sealDirectNote(ME, 'second after reset', alice, peerOf(me), aliceNew.io); // a CONTINUATION of the new session
  return { me, alice, meIO, aliceNew, f2: f2!, f3: f3! };
}

test('N-R5e without an adopt policy nothing changes: the new first frame is a held desync and the stored row is byte-identical', async () => {
  const { me, alice, meIO, f2 } = await aliceResets();
  const before = JSON.stringify(meIO.rows.get(ALICE));
  const r = await openDirectNoteStagedTyped(ALICE, f2, me, peerOf(alice), meIO.io);
  assert.deepEqual(r, { failed: true, kind: 'desync', cause: 'ratchet-receive-failed' });
  assert.equal(JSON.stringify(meIO.rows.get(ALICE)), before);
});

test('N-R5a a policy that says NO (replayed / older frame) leaves the desync and the row untouched; the policy is asked with unconfirmed=false for a confirmed session', async () => {
  const { me, alice, meIO, f2 } = await aliceResets();
  const before = JSON.stringify(meIO.rows.get(ALICE));
  const asked: boolean[] = [];
  const r = await openDirectNoteStagedTyped(ALICE, f2, me, peerOf(alice), meIO.io, (s) => { asked.push(s.unconfirmed); return false; });
  assert.deepEqual(r, { failed: true, kind: 'desync', cause: 'ratchet-receive-failed' });
  assert.deepEqual(asked, [false]);
  assert.equal(JSON.stringify(meIO.rows.get(ALICE)), before, 'the session was not rewound or replaced');
});

test('N-R5b a policy that says YES replaces the session: the open reports replaced, commit stores the NEW session, and a reply from it opens on Alice\'s new side (they converge)', async () => {
  const { me, alice, meIO, aliceNew, f2 } = await aliceResets();
  const r = await openDirectNoteStagedTyped(ALICE, f2, me, peerOf(alice), meIO.io, () => true);
  assert.ok(!('failed' in r)); const staged = r as { plaintext: string; replaced?: boolean; commit: () => Promise<void> };
  assert.equal(staged.plaintext, 'after the reset'); assert.equal(staged.replaced, true);
  await staged.commit();
  const reply = await sealDirectNote(ALICE, 'hello again', me, peerOf(alice), meIO.io); // continues the ADOPTED session (no new initiate)
  const back = await openDirectNoteStagedTyped(ME, reply!, alice, peerOf(me), aliceNew.io);
  assert.ok(!('failed' in back)); assert.equal((back as { plaintext: string }).plaintext, 'hello again');
  (back as { release: () => void }).release(); // a staged open holds the per-peer lock until it ends
});

test('N-R5b2 an ordinary frame on a healthy session is NOT a replacement: replaced is absent and the policy is never asked', async () => {
  const me = ratchetIdentity(), alice = ratchetIdentity();
  const meIO = memIO(), aliceIO = memIO();
  const a = await sealDirectNote(ME, 'one', alice, peerOf(me), aliceIO.io);
  const b = await sealDirectNote(ME, 'two', alice, peerOf(me), aliceIO.io);
  const s1 = await openDirectNoteStagedTyped(ALICE, a!, me, peerOf(alice), meIO.io, () => { throw new Error('asked'); });
  await (s1 as { commit: () => Promise<void> }).commit();
  const s2 = await openDirectNoteStagedTyped(ALICE, b!, me, peerOf(alice), meIO.io, () => { throw new Error('asked'); });
  assert.ok(!('failed' in s2)); assert.equal((s2 as { replaced?: boolean }).replaced, undefined);
  await (s2 as { commit: () => Promise<void> }).commit();
});

test('N-R5d only a FIRST frame can replace a session: a REPLAYED frame of the old, confirmed session (no handshake header) stays a held desync even when the policy says yes', async () => {
  const me = ratchetIdentity(), alice = ratchetIdentity();
  const meIO = memIO(), aliceIO = memIO();
  const open = async (io: RatchetIO, who: string, body: string, selfId: RatchetIdentity, peerId: RatchetIdentity, adopt?: () => boolean) => {
    const r = await openDirectNoteStagedTyped(who, body, selfId, peerOf(peerId), io, adopt);
    if (!('failed' in r)) await r.commit();
    return r;
  };
  assert.ok(!('failed' in await open(meIO.io, ALICE, (await sealDirectNote(ME, 'one', alice, peerOf(me), aliceIO.io))!, me, alice)));
  const reply = await sealDirectNote(ALICE, 'reply', me, peerOf(alice), meIO.io); // my reply confirms the session on Alice's side
  assert.ok(!('failed' in await open(aliceIO.io, ME, reply!, alice, me)));
  const later = (await sealDirectNote(ME, 'two', alice, peerOf(me), aliceIO.io))!; // a plain continuation: no handshake header any more
  assert.ok(!('failed' in await open(meIO.io, ALICE, later, me, alice)));
  const before = JSON.stringify(meIO.rows.get(ALICE));
  const replay = await openDirectNoteStagedTyped(ALICE, later, me, peerOf(alice), meIO.io, () => true);
  assert.deepEqual(replay, { failed: true, kind: 'desync', cause: 'ratchet-receive-failed' }, 'a replayed non-first frame cannot rewind or replace the session');
  assert.equal(JSON.stringify(meIO.rows.get(ALICE)), before);
});

test('N-R5f a LATER frame of the peer\'s new session also heals when the first one was lost: the initiator keeps the handshake header on every frame until it hears back (policy permitting)', async () => {
  const { me, alice, meIO, f3 } = await aliceResets(); // f2 never delivered
  const r = await openDirectNoteStagedTyped(ALICE, f3, me, peerOf(alice), meIO.io, () => true);
  assert.ok(!('failed' in r)); assert.equal((r as { replaced?: boolean }).replaced, true);
  assert.equal((r as { plaintext: string }).plaintext, 'second after reset');
  (r as { release: () => void }).release();
});

test('N-R6a our session is UNCONFIRMED (we initiated, nothing received): the policy is asked with unconfirmed=true', async () => {
  const me = ratchetIdentity(), alice = ratchetIdentity();
  const meIO = memIO(), aliceNew = memIO();
  assert.ok(await sealDirectNote(ALICE, 'my own first frame', me, peerOf(alice), meIO.io)); // I reset first and wrote
  const theirs = await sealDirectNote(ME, 'their first frame', alice, peerOf(me), aliceNew.io);
  const asked: boolean[] = [];
  const r = await openDirectNoteStagedTyped(ALICE, theirs!, me, peerOf(alice), meIO.io, (s) => { asked.push(s.unconfirmed); return true; });
  assert.deepEqual(asked, [true]);
  assert.ok(!('failed' in r)); assert.equal((r as { replaced?: boolean }).replaced, true);
  (r as { release: () => void }).release();
});

// ── the pure policy ──
const NOW = Date.parse('2026-10-31T12:00:00.000Z');
const facts = (o: Partial<AdoptFacts> = {}): AdoptFacts => ({
  unconfirmed: false, ownFingerprint: 'bb', peerFingerprint: 'aa', sentAtMs: NOW - 1000, newestStoredAtMs: NOW - 60_000, nowMs: NOW, ...o,
});

test('N-R5a policy: a first frame whose signed sent_at is NOT newer than the newest stored note from that contact is refused (replay), newer is allowed', () => {
  assert.equal(mayAdoptFirstFrame(facts({ sentAtMs: NOW - 60_000 })), false, 'equal to the newest stored');
  assert.equal(mayAdoptFirstFrame(facts({ sentAtMs: NOW - 120_000 })), false, 'older');
  assert.equal(mayAdoptFirstFrame(facts({ sentAtMs: NOW - 59_999 })), true, 'one ms newer');
});

test('N-R5a policy (Flint #2352/#2360) UPPER BOUND: a first frame dated beyond now + 5 min is refused, in both the stored and the none-stored case; the edge is exact', () => {
  assert.equal(mayAdoptFirstFrame(facts({ sentAtMs: NOW + FUTURE_SLACK_MS })), true, 'now + slack exactly: adopts');
  assert.equal(mayAdoptFirstFrame(facts({ sentAtMs: NOW + FUTURE_SLACK_MS + 1 })), false, 'one ms beyond: refused');
  assert.equal(mayAdoptFirstFrame(facts({ newestStoredAtMs: null, sentAtMs: NOW + FUTURE_SLACK_MS })), true, 'none stored, now + slack: adopts');
  assert.equal(mayAdoptFirstFrame(facts({ newestStoredAtMs: null, sentAtMs: NOW + FUTURE_SLACK_MS + 1 })), false, 'none stored, one ms beyond: refused');
  assert.equal(mayAdoptFirstFrame(facts({ newestStoredAtMs: null, sentAtMs: NOW + 30 * 24 * 3_600_000 })), false, 'none stored, a month ahead: refused (the relay-window check only looks backwards)');
});

test('N-R5a policy: with NO stored note from that contact the frame must be within the 7-day relay window of now', () => {
  assert.equal(mayAdoptFirstFrame(facts({ newestStoredAtMs: null, sentAtMs: NOW - RELAY_WINDOW_MS + 1 })), true);
  assert.equal(mayAdoptFirstFrame(facts({ newestStoredAtMs: null, sentAtMs: NOW - RELAY_WINDOW_MS - 1 })), false);
});

test('N-R5a policy: a sent_at or clock that is not a finite number refuses; so does a stored time that is not', () => {
  for (const bad of [NaN, Infinity, -Infinity]) {
    assert.equal(mayAdoptFirstFrame(facts({ sentAtMs: bad })), false);
    assert.equal(mayAdoptFirstFrame(facts({ nowMs: bad })), false);
    assert.equal(mayAdoptFirstFrame(facts({ newestStoredAtMs: bad })), false);
  }
});

test('N-R6 policy: while OUR session is unconfirmed the LOWER fingerprint wins (lowercase hex compare): the lower side refuses, the higher side adopts; a confirmed session has no tie-break', () => {
  assert.equal(mayAdoptFirstFrame(facts({ unconfirmed: true, ownFingerprint: 'aa', peerFingerprint: 'bb' })), false, 'we are lower: ours wins');
  assert.equal(mayAdoptFirstFrame(facts({ unconfirmed: true, ownFingerprint: 'bb', peerFingerprint: 'aa' })), true, 'we are higher: adopt theirs');
  assert.equal(mayAdoptFirstFrame(facts({ unconfirmed: true, ownFingerprint: 'AA', peerFingerprint: 'bb' })), false, 'case does not matter');
  assert.equal(mayAdoptFirstFrame(facts({ unconfirmed: true, ownFingerprint: 'BB', peerFingerprint: 'aa' })), true, 'case does not matter: upper-case B is still HIGHER than a (a raw string compare would say lower)');
  assert.equal(mayAdoptFirstFrame(facts({ unconfirmed: false, ownFingerprint: 'aa', peerFingerprint: 'bb' })), true, 'confirmed: no tie-break');
});

// A type-level reference so the unused-import rule does not drop RatchetIO from the intended surface of this file.
export type _IO = RatchetIO;
