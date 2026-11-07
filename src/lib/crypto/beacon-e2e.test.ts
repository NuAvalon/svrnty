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

test('3a. R6 (Flint §11, GAP-1): a B holding a GARBAGE share learns NOTHING about whether A deposited — B\'s whole view is identical in both worlds', () => {
  // RED on 3c30ccd BY DESIGN. The old test 3 asserted "match fires + A's mailbox gets B's share" as ACCEPTABLE; that blessed the leak
  // (B receives A's genuine share while committing nothing). This states the actual requirement as an indistinguishability game:
  // everything B can observe (the deposit response and its own mailbox) must be the same whether or not A has deposited.
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[2];
  const B = dir[5];
  const epoch = 2960;
  const sB = deriveSharedSecret(B.sk, A.pk);
  const slot = slotId(sB, epoch);
  const garbage = beaconPubkey(identityScalar(ed25519.utils.randomSecretKey())).toHex(); // not b·H: B commits no genuine trust

  const bView = (aDeposited: boolean) => {
    const matcher = new BeaconMatcher(ring);
    if (aDeposited) {
      const A1 = genuineDeposit(ring, A, 2, B, epoch);
      matcher.deposit(A1.slot, A1.dep);
    }
    const lrsB = ringSign(ring, 5, B.scalar, slot, BEACON_MSG); // valid enrolled-member signature
    const res = matcher.deposit(slot, { tag: lrsB.tag, share: garbage, lrs: lrsB });
    return { res, mailbox: matcher.poll(lrsB.tag), confirms: matcher.pollConfirm(lrsB.tag) };
  };
  assert.deepEqual(bView(false), bView(false), 'control: B\'s view is deterministic within one world, so a difference below is caused by A\'s deposit, not noise');
  assert.deepEqual(bView(true), bView(false), 'B must not be able to tell "A deposited" from "A did not" by depositing a garbage share');
});

test('3c. R6 (Flint attack review): a B with a SYBIL key C who deposits a WELL-FORMED share learns NOTHING about whether A deposited', () => {
  // RED on 4df13ce BY DESIGN, and it must stay red under "Option 2" (a DLEQ saying "the share belongs to SOME enrolled key"):
  // C is a genuinely enrolled key and C's share is a genuine DH share (c·H), so every such check passes. B hands C the slot and the
  // pair base H (both derivable from S_pair), C deposits at the A–B slot, the match fires, and A's genuine share lands in C's
  // mailbox: B learns "A trusts B" at the cost of one enrollment. It goes green only when a deposit must be bound to the PAIR.
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[2];
  const B = dir[5];
  const C = dir[1]; // a second enrolled identity B controls
  const epoch = 2960;
  const sAB = deriveSharedSecret(B.sk, A.pk);
  const slot = slotId(sAB, epoch);
  const H = bondBase(sAB, epoch);

  const cView = (aDeposited: boolean) => {
    const matcher = new BeaconMatcher(ring);
    if (aDeposited) {
      const A1 = genuineDeposit(ring, A, 2, B, epoch);
      matcher.deposit(A1.slot, A1.dep);
    }
    const lrsC = ringSign(ring, 1, C.scalar, slot, BEACON_MSG); // valid enrolled-member signature (C's own key)
    const res = matcher.deposit(slot, { tag: lrsC.tag, share: depositShare(H, C.scalar).toHex(), lrs: lrsC }); // genuine c·H
    return { res, mailbox: matcher.poll(lrsC.tag), confirms: matcher.pollConfirm(lrsC.tag) };
  };
  assert.deepEqual(cView(false), cView(false), 'control: C\'s view is deterministic within one world');
  assert.deepEqual(cView(true), cView(false), 'a sybil with a well-formed share must not be able to tell "A deposited" from "A did not"');
});

test('3b. a garbage share never produces a bond (no false mutual), whatever else is delivered', () => {
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[2];
  const B = dir[5];
  const epoch = 2960;
  const matcher = new BeaconMatcher(ring);
  const A1 = genuineDeposit(ring, A, 2, B, epoch);
  matcher.deposit(A1.slot, A1.dep);
  const sB = deriveSharedSecret(B.sk, A.pk);
  const slot = slotId(sB, epoch);
  const garbage = beaconPubkey(identityScalar(ed25519.utils.randomSecretKey())).toHex();
  const lrsB = ringSign(ring, 5, B.scalar, slot, BEACON_MSG);
  matcher.deposit(slot, { tag: lrsB.tag, share: garbage, lrs: lrsB });
  const toA = matcher.poll(A1.dep.tag);
  const toB = matcher.poll(lrsB.tag);
  // a bond can light only if BOTH sides hold a counterpart share and their M agree; a garbage share must never make them agree
  const lit = toA.length > 0 && toB.length > 0 && bondsMatch(bondToken(P.fromHex(toA[0]), A.scalar), bondToken(P.fromHex(toB[0]), B.scalar));
  assert.equal(lit, false, 'garbage share => inconsistent M => no bond');
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
