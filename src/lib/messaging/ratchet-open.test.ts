// src/lib/messaging/ratchet-open.test.ts
// #720 contract v5.3 (Flint #2052): every ratchet open failure is TYPED local|verdict, and UNKNOWN IS LOCAL.
// Real ratchet crypto for the causes inside the open; injected loaders for the classifier. Run: npx tsx --test src/lib/messaging/ratchet-open.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { memIO } from './ratchet-test-io';
import { sealDirectNote, openDirectNoteStagedTyped, openDirectNoteStaged, type OpenFailure, type StagedOpen } from './direct-session';
import { openRatchetClassified, type RatchetOpenLoaders } from './ratchet-open';

function ident(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const isFail = (r: StagedOpen | OpenFailure): r is OpenFailure => 'failed' in r;
const ME = 'fp-me';

test('T1 typed causes inside the open: malformed frame / wrong-key ciphertext / first-frame rejected are VERDICTS; an unreadable session row and a corrupt snapshot are LOCAL', async () => {
  const [me, them, stranger] = [ident(), ident(), ident()];
  const frame = (await sealDirectNote(ME, 'secret', them, peerOf(me), memIO().io))!;
  // malformed frame
  const malformed = await openDirectNoteStagedTyped('p', 'not-a-ratchet-body', me, peerOf(them), memIO().io);
  assert.deepEqual(malformed, { failed: true, kind: 'verdict', cause: 'malformed-frame' });
  // a frame sealed to someone else cannot be accepted as a first frame
  const wrongKey = (await sealDirectNote(ME, 'x', them, peerOf(stranger), memIO().io))!;
  const first = await openDirectNoteStagedTyped('p', wrongKey, me, peerOf(them), memIO().io);
  assert.ok(isFail(first) && first.kind === 'verdict' && first.cause === 'first-frame-rejected');
  // an unreadable session row is THIS device's problem
  const bad = memIO(); bad.rows.set('p', { state: 'unreadable' } as never);
  const unreadable = await openDirectNoteStagedTyped('p', frame, me, peerOf(them), bad.io);
  assert.deepEqual(unreadable, { failed: true, kind: 'local', cause: 'session-row-unreadable' });
  // a corrupt snapshot likewise
  const corrupt = memIO(); corrupt.rows.set('p', { state: 'ok', snapshot: { garbage: true } as never, version: 1 });
  const snap = await openDirectNoteStagedTyped('p', frame, me, peerOf(them), corrupt.io);
  assert.ok(isFail(snap) && snap.kind === 'local' && snap.cause === 'session-snapshot-corrupt', JSON.stringify(snap));
  // a healthy open still works, and the legacy null-returning wrapper agrees with the typed one on every failure
  const ok = await openDirectNoteStagedTyped('p', frame, me, peerOf(them), memIO().io);
  assert.ok(!isFail(ok) && ok.plaintext === 'secret'); ok.release();
  assert.equal(await openDirectNoteStaged('p', 'not-a-ratchet-body', me, peerOf(them), memIO().io), null);
  assert.equal(await openDirectNoteStaged('p', frame, me, peerOf(them), bad.io), null);
});

const okLoaders = (over: Partial<RatchetOpenLoaders> = {}): RatchetOpenLoaders => {
  const staged = { plaintext: 'hi', commit: async () => {}, release: () => {} } as StagedOpen;
  return { loadSelf: async () => ident(), contactExists: async () => true, loadPeer: async () => peerOf(ident()), open: async () => staged, ...over };
};
const kindOf = (r: StagedOpen | OpenFailure) => (isFail(r) ? `${r.kind}:${r.cause}` : 'opened');

test('T2 classifier: own-key missing / contact vanished / ANY throw anywhere => LOCAL; an admitted contact with no PQ card => VERDICT; typed failures pass through; success passes through', async () => {
  assert.equal(kindOf(await openRatchetClassified(okLoaders())), 'opened');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ loadSelf: async () => null }))), 'local:own-ratchet-identity-unavailable');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ contactExists: async () => false }))), 'local:contact-missing-after-admit');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ loadPeer: async () => null }))), 'verdict:peer-card-has-no-pq-keys');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ open: async () => ({ failed: true, kind: 'verdict', cause: 'ratchet-receive-failed' }) }))), 'verdict:ratchet-receive-failed');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ open: async () => ({ failed: true, kind: 'local', cause: 'session-row-unreadable' }) }))), 'local:session-row-unreadable');
});

test('T3 v5.3 NEG (Flint): a THROW inside unlock/assemble (or any other loader or the open itself) is LOCAL, never a verdict', async () => {
  const boom = async () => { throw new Error('unlock failed'); };
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ loadSelf: boom as never }))), 'local:open-threw');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ contactExists: boom as never }))), 'local:open-threw');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ loadPeer: boom as never }))), 'local:open-threw');
  assert.equal(kindOf(await openRatchetClassified(okLoaders({ open: boom as never }))), 'local:open-threw');
});
