// src/lib/crypto/beacon-e2e.test.ts
// Run: npx tsx --test src/lib/crypto/beacon-e2e.test.ts
//
// #588 END-TO-END adversarial suite — composes beacon-lrs + beacon-psi + beacon-matcher the way the
// real deposit flow does, then runs Flint's three hostile scenarios + the consistent-M bond gate.
// This is the PROTOCOL-level empirical Flint re-confirms on (crypto-core unit tests are necessary-
// not-sufficient; THIS is where the primitives meet the server).
//
//   1. GENUINE mutual — A & B both genuinely deposit ⇒ match ⇒ both derive the SAME bond M.
//   2. OP-5 (de-anon as B) — A's LONE deposit is undetectable to B via the oblivious matcher.
//   3. probe-oracle + garbage-share — B deposits a GARBAGE share to probe: the match EVENT fires
//      (A learns "someone deposited" = symmetric, acceptable C2) but the consistent-M gate REJECTS
//      the bond (A's M ≠ B's M) ⇒ NO false bond fabricated.
//   4. PO-2 sybil — A controls two enrolled ids and self-matches: yields a bond with ITSELF only,
//      never a forged bond with B (B's secret never participates).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ristretto255 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { concatBytes } from '@noble/curves/utils.js';
import {
  deriveSharedSecret,
  bondBase,
  identityScalar,
  depositShare,
  bondToken,
  bondsMatch,
} from './beacon-psi';
import { beaconPubkey, ringSign } from './beacon-lrs';
import { BeaconMatcher, BEACON_MSG, type BeaconDeposit } from './beacon-matcher';

const P = ristretto255.Point;

function mintIdentity() {
  const sk = ed25519.utils.randomSecretKey();
  const pk = ed25519.getPublicKey(sk);
  const scalar = identityScalar(sk); // same scalar used for LRS membership AND DH-PSI share
  return { sk, pk, scalar, pubkey: beaconPubkey(scalar) };
}
type Identity = ReturnType<typeof mintIdentity>;

/** The matcher slot id for a pair+epoch — derived from the shared secret (only the pair can compute it). */
function slotId(sharedSecret: Uint8Array, epoch: number): Uint8Array {
  return sha256(concatBytes(sharedSecret, new TextEncoder().encode(`|slot|${epoch}`)));
}

/** Build a genuine deposit for `me` toward `peer` at the given epoch (membership LRS + DH-PSI share). */
function genuineDeposit(ring: Identity['pubkey'][], me: Identity, meIdx: number, peer: Identity, epoch: number): { slot: Uint8Array; dep: BeaconDeposit } {
  const s = deriveSharedSecret(me.sk, peer.pk);
  const slot = slotId(s, epoch);
  const H = bondBase(s, epoch);
  const lrs = ringSign(ring, meIdx, me.scalar, slot, BEACON_MSG);
  const share = depositShare(H, me.scalar).toHex();
  return { slot, dep: { tag: lrs.tag, share, lrs } };
}

test('1. GENUINE mutual: both deposit ⇒ match ⇒ identical bond M', () => {
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[1];
  const B = dir[4];
  const epoch = 2960;
  const matcher = new BeaconMatcher(ring);

  const A1 = genuineDeposit(ring, A, 1, B, epoch);
  const B1 = genuineDeposit(ring, B, 4, A, epoch);
  assert.deepEqual(A1.slot, B1.slot, 'both derive the same pair slot');

  matcher.deposit(A1.slot, A1.dep);
  const r = matcher.deposit(B1.slot, B1.dep);
  assert.ok(r.matched, 'two genuine members ⇒ match');

  // Each polls its own tag, gets the counterpart share, computes the bond.
  const D_B = P.fromHex(matcher.poll(A1.dep.tag)[0]);
  const D_A = P.fromHex(matcher.poll(B1.dep.tag)[0]);
  const M_A = bondToken(D_B, A.scalar);
  const M_B = bondToken(D_A, B.scalar);
  assert.ok(bondsMatch(M_A, M_B), 'consistent-M ⇒ genuine mutual bond');
});

test('2. OP-5 de-anon-as-B: A\'s lone deposit is undetectable to B', () => {
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[0];
  const B = dir[3];
  const epoch = 2960;
  const matcher = new BeaconMatcher(ring);

  const A1 = genuineDeposit(ring, A, 0, B, epoch);
  matcher.deposit(A1.slot, A1.dep);

  // B knows the slot (shares s) but the matcher exposes NO occupancy — B's mailbox is empty.
  const B1 = genuineDeposit(ring, B, 3, A, epoch);
  assert.deepEqual(matcher.poll(B1.dep.tag), [], 'B cannot detect A\'s lone deposit (no-peek)');
});

test('3. probe-oracle + garbage share: match-event symmetric, but NO false bond', () => {
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[2];
  const B = dir[5];
  const epoch = 2960;
  const matcher = new BeaconMatcher(ring);

  // A genuinely deposits.
  const A1 = genuineDeposit(ring, A, 2, B, epoch);
  matcher.deposit(A1.slot, A1.dep);

  // B PROBES: valid LRS membership, but a GARBAGE DH-PSI share (not b·H).
  const sB = deriveSharedSecret(B.sk, A.pk);
  const slot = slotId(sB, epoch);
  const garbage = beaconPubkey(identityScalar(ed25519.utils.randomSecretKey())).toHex(); // random point
  const lrsB = ringSign(ring, 5, B.scalar, slot, BEACON_MSG);
  const rB = matcher.deposit(slot, { tag: lrsB.tag, share: garbage, lrs: lrsB });
  assert.ok(rB.matched, 'match EVENT fires (B cannot deposit invisibly)');

  // Symmetric: A learned the event too (A's mailbox got B's (garbage) share).
  assert.equal(matcher.poll(A1.dep.tag).length, 1, 'A simultaneously learned B deposited (symmetric)');

  // But the consistent-M bond gate REJECTS: A's M (from garbage) ≠ B's M (from A's real share).
  const H = bondBase(sB, epoch);
  const D_A = P.fromHex(matcher.poll(lrsB.tag)[0]);
  const M_B = bondToken(D_A, B.scalar); // B's bond from A's genuine share
  const M_A = bondToken(P.fromHex(garbage), A.scalar); // A's bond from B's garbage share
  assert.ok(!bondsMatch(M_A, M_B), 'garbage share ⇒ inconsistent M ⇒ NO false bond');
  void H;
});

test('4. PO-2 sybil: self-match yields a bond with SELF only, never a forged bond with B', () => {
  const dir = Array.from({ length: 6 }, mintIdentity);
  const A1id = dir[0];
  const A2id = dir[1]; // A controls BOTH enrolled ids
  const B = dir[4];
  const ring = dir.map((d) => d.pubkey);
  const epoch = 2960;
  const matcher = new BeaconMatcher(ring);

  // A can locate the A1–B slot (A controls A1 ⇒ knows s_{A1,B}); A deposits as A1 AND A2 there.
  const sA1B = deriveSharedSecret(A1id.sk, B.pk);
  const slot = slotId(sA1B, epoch);
  const H = bondBase(sA1B, epoch);
  const depA1: BeaconDeposit = (() => { const l = ringSign(ring, 0, A1id.scalar, slot, BEACON_MSG); return { tag: l.tag, share: depositShare(H, A1id.scalar).toHex(), lrs: l }; })();
  const depA2: BeaconDeposit = (() => { const l = ringSign(ring, 1, A2id.scalar, slot, BEACON_MSG); return { tag: l.tag, share: depositShare(H, A2id.scalar).toHex(), lrs: l }; })();

  matcher.deposit(slot, depA1);
  const r = matcher.deposit(slot, depA2);
  assert.ok(r.matched, 'two distinct enrolled ids ⇒ the matcher matches (distinctness is enrolled, not pair)');

  // But the resulting bond is A1·A2·H — a bond with SELF, NOT a bond involving B's secret.
  const M1 = bondToken(P.fromHex(matcher.poll(depA1.tag)[0]), A1id.scalar); // a1·(a2·H)
  const M2 = bondToken(P.fromHex(matcher.poll(depA2.tag)[0]), A2id.scalar); // a2·(a1·H)
  assert.ok(bondsMatch(M1, M2), 'sybil self-bond is internally consistent (mutual-with-self)');

  // The forgery that MATTERS — a mutual with B — is impossible: B never deposited, B's secret b is
  // absent, so no bond M=a·b·H with B exists. The sybil gained nothing about B.
  const bHonest = genuineDeposit(ring, B, 4, A1id, epoch);
  assert.equal(matcher.poll(bHonest.dep.tag).length, 0, 'B has no delivered share ⇒ no forged A-B bond');
});
