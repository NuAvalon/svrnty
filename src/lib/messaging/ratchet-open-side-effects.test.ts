// src/lib/messaging/ratchet-open-side-effects.test.ts
// #720 T1 (Flint #186298, contract v5.x): a FAILED ratchet open is side-effect-free. The persisted per-peer session row is byte-identical before and
// after, nothing is written, and the session is not damaged: the next legitimate frame still opens and commits. Without this, a hold-and-retry loop
// (T2) would re-open the same frame every poll and each failure could advance a chain, grow skipped keys or corrupt the state it is trying to heal.
// Real TripleRatchet, real frames, in-memory session storage with a call log. Run: npx tsx --test src/lib/messaging/ratchet-open-side-effects.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { memIO } from './ratchet-test-io';
import { sealDirectNote, openDirectNoteStagedTyped, type OpenFailure, type StagedOpen } from './direct-session';

function ident(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const isFail = (r: StagedOpen | OpenFailure): r is OpenFailure => 'failed' in r;
const ME = 'fp-me', THEM = 'fp-them'; // each side keys its session row by the OTHER side's label

/** THEM sends frames to ME; ME has opened and committed the first `committed` of them. */
async function established(committed = 2) {
  const [me, them] = [ident(), ident()];
  const theirIO = memIO(), myIO = memIO();
  const frames: string[] = [];
  for (let i = 0; i < committed + 1; i++) frames.push((await sealDirectNote(ME, 'message ' + i, them, peerOf(me), theirIO.io))!);
  for (let i = 0; i < committed; i++) {
    const r = await openDirectNoteStagedTyped(THEM, frames[i], me, peerOf(them), myIO.io);
    assert.ok(!isFail(r), 'setup: frame ' + i + ' must open');
    await (r as StagedOpen).commit();
  }
  return { me, them, myIO, frames, next: frames[committed] };
}
const snap = (io: ReturnType<typeof memIO>, fp = THEM) => JSON.stringify(io.rows.get(fp));
const puts = (io: ReturnType<typeof memIO>) => io.log.filter((l) => l.startsWith('put'));

test('T1a: replaying a SPENT frame fails as a verdict and leaves the persisted session byte-identical, with no write; the next real frame still opens', async () => {
  const s = await established(2);
  const before = snap(s.myIO), putsBefore = puts(s.myIO).length;
  const r = await openDirectNoteStagedTyped(THEM, s.frames[0], s.me, peerOf(s.them), s.myIO.io);
  assert.ok(isFail(r) && r.kind === 'verdict', JSON.stringify(r));
  assert.equal(snap(s.myIO), before, 'the stored session row is byte-identical');
  assert.equal(puts(s.myIO).length, putsBefore, 'nothing was written');
  const ok = await openDirectNoteStagedTyped(THEM, s.next, s.me, peerOf(s.them), s.myIO.io);
  assert.ok(!isFail(ok) && ok.plaintext === 'message 2', 'the session was not damaged by the failed open');
  await ok.commit();
});

test('T1b: a TAMPERED frame (authentication fails) leaves the session untouched; repeating the failure 20 times changes nothing (a retry loop cannot erode the session)', async () => {
  const s = await established(2);
  const before = snap(s.myIO);
  const flip = (f: string) => f.slice(0, Math.floor(f.length / 2)) + (f[Math.floor(f.length / 2)] === 'A' ? 'B' : 'A') + f.slice(Math.floor(f.length / 2) + 1);
  const tampered = flip(s.next);
  assert.notEqual(tampered, s.next);
  for (let i = 0; i < 20; i++) {
    const r = await openDirectNoteStagedTyped(THEM, tampered, s.me, peerOf(s.them), s.myIO.io);
    assert.ok(isFail(r), 'attempt ' + i);
  }
  assert.equal(snap(s.myIO), before);
  assert.equal(puts(s.myIO).length, 2, 'only the two setup commits ever wrote');
  const ok = await openDirectNoteStagedTyped(THEM, s.next, s.me, peerOf(s.them), s.myIO.io);
  assert.ok(!isFail(ok) && ok.plaintext === 'message 2');
  await ok.commit();
});

test('T1c: a frame from a DIFFERENT session / stranger, and a malformed body, against an existing session: byte-identical, no write', async () => {
  const s = await established(2);
  const before = snap(s.myIO);
  const [other, otherPeer] = [ident(), ident()];
  const foreign = (await sealDirectNote(ME, 'from someone else', otherPeer, peerOf(s.me), memIO().io))!;
  void other;
  for (const body of [foreign, 'not-a-ratchet-body', '']) {
    const r = await openDirectNoteStagedTyped(THEM, body, s.me, peerOf(s.them), s.myIO.io);
    assert.ok(isFail(r));
  }
  assert.equal(snap(s.myIO), before);
  assert.equal(puts(s.myIO).length, 2);
});

test('T1d: with NO session row, a failing first frame creates NO row and writes nothing (a failed acceptFirst cannot plant a half-session)', async () => {
  const [me, them, stranger] = [ident(), ident(), ident()];
  const io = memIO();
  const sealedToSomeoneElse = (await sealDirectNote(ME, 'x', them, peerOf(stranger), memIO().io))!;
  const r = await openDirectNoteStagedTyped(THEM, sealedToSomeoneElse, me, peerOf(them), io.io);
  assert.ok(isFail(r) && r.cause === 'first-frame-rejected', JSON.stringify(r));
  assert.equal(io.rows.size, 0, 'no row was created');
  assert.equal(puts(io).length, 0);
});

test('T1e: a failed open ends its lock: the next open for the same peer is not blocked (no leaked per-peer lock after any failure path)', async () => {
  const s = await established(1);
  for (let i = 0; i < 5; i++) {
    const r = await openDirectNoteStagedTyped(THEM, s.frames[0], s.me, peerOf(s.them), s.myIO.io); // spent
    assert.ok(isFail(r));
  }
  const ok = await Promise.race([
    openDirectNoteStagedTyped(THEM, s.next, s.me, peerOf(s.them), s.myIO.io),
    new Promise<'LOCK-LEAKED'>((res) => setTimeout(() => res('LOCK-LEAKED'), 3000)),
  ]);
  assert.notEqual(ok, 'LOCK-LEAKED');
  assert.ok(!isFail(ok as StagedOpen | OpenFailure));
  await (ok as StagedOpen).commit();
});
