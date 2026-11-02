// peerRatchetStatus: the READ-ONLY observed-capability read the D2 line uses. Real ratchet crypto, in-memory session storage.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { openDirectNote, ownerBoundRatchetIO, peerRatchetStatus, sealDirectNote } from './direct-session';
import { memIO } from './ratchet-test-io';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const ME = 'fp-me', THEM = 'fp-them';

test('no session => not-observed, and the read writes nothing', async () => {
  const s = memIO();
  assert.equal(await peerRatchetStatus(ME, THEM, s.io), 'not-observed');
  assert.deepEqual(s.log, [`read:${THEM}`]);
});

test('an initiator-only session (we sent, they never sent a frame we opened) => not-observed', async () => {
  const me = ratchetIdentity(), them = ratchetIdentity(), s = memIO();
  assert.ok(await sealDirectNote(THEM, 'old ratchet send', me, peerOf(them), s.io));
  const before = JSON.stringify([...s.rows]);
  assert.equal(await peerRatchetStatus(ME, THEM, s.io), 'not-observed');
  assert.equal(JSON.stringify([...s.rows]), before, 'read-only');
});

test('a peer whose frame we OPENED => observed', async () => {
  const me = ratchetIdentity(), them = ratchetIdentity(), meIO = memIO(), themIO = memIO();
  const frame = await sealDirectNote(ME, 'hi', them, peerOf(me), themIO.io);
  assert.equal(await openDirectNote(THEM, frame!, me, peerOf(them), meIO.io), 'hi');
  assert.equal(await peerRatchetStatus(ME, THEM, meIO.io), 'observed');
});

test('an unreadable row, or a store open for another identity => unknown (the UI then says nothing), never a guess', async () => {
  const bad = memIO();
  bad.rows.set(THEM, { state: 'unreadable' });
  assert.equal(await peerRatchetStatus(ME, THEM, bad.io), 'unknown');
  const other = memIO();
  assert.equal(await peerRatchetStatus(ME, THEM, ownerBoundRatchetIO(ME, () => 'someone-else', other.io)), 'unknown');
  assert.deepEqual(other.log, [], 'the wrong-owner read never reached the storage');
});
