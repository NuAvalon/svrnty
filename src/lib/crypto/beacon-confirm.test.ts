// src/lib/crypto/beacon-confirm.test.ts
// Run: npx tsx --test src/lib/crypto/beacon-confirm.test.ts
//
// #588 FINDING-1 + reflection re-verify (Flint #174179, #174198): the mandatory, TAG-BOUND
// bond-confirmation exchange. A party lights "mutual" ONLY when the peer's confirm == H(myM‖peerTag).
//   • GENUINE: same M ⇒ confirms agree ⇒ BOTH light.
//   • GARBAGE-PROBE: B's garbage share ⇒ A's M ≠ B's M ⇒ confirms disagree ⇒ NEITHER lights.
//   • REFLECTION: B reads A's confirm and mirrors it back ⇒ it's bound to A's tag, not B's ⇒ A's
//     peer-tag check FAILS ⇒ A does NOT light. (This is the attack the symmetric v1 confirm allowed.)
//   • No confirm channel pre-match.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ristretto255, ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/curves/utils.js';
import {
  deriveSharedSecret,
  bondBase,
  identityScalar,
  depositShare,
  bondToken,
  bondConfirm,
  mutualConfirmed,
} from './beacon-psi';
import { beaconPubkey, ringSign } from './beacon-lrs';
import { BeaconMatcher, BEACON_MSG, type BeaconDeposit } from './beacon-matcher';

const P = ristretto255.Point;
function mintIdentity() {
  const sk = ed25519.utils.randomSecretKey();
  const pk = ed25519.getPublicKey(sk);
  const scalar = identityScalar(sk);
  return { sk, pk, scalar, pubkey: beaconPubkey(scalar) };
}
function slotId(s: Uint8Array, epoch: number): Uint8Array {
  return sha256(concatBytes(s, new TextEncoder().encode(`|slot|${epoch}`)));
}
function dep(ring: ReturnType<typeof beaconPubkey>[], idx: number, scalar: bigint, slot: Uint8Array, share: string): BeaconDeposit {
  const lrs = ringSign(ring, idx, scalar, slot, BEACON_MSG);
  return { tag: lrs.tag, share, lrs };
}

test('GENUINE: matching M + tag-bound confirms ⇒ BOTH light', () => {
  const d = Array.from({ length: 6 }, mintIdentity);
  const ring = d.map((x) => x.pubkey);
  const A = d[1], B = d[4], epoch = 2960;
  const m = new BeaconMatcher(ring);
  const s = deriveSharedSecret(A.sk, B.pk);
  const slot = slotId(s, epoch);
  const H = bondBase(s, epoch);
  const dA = dep(ring, 1, A.scalar, slot, depositShare(H, A.scalar).toHex());
  const dB = dep(ring, 4, B.scalar, slot, depositShare(H, B.scalar).toHex());
  m.deposit(slot, dA); m.deposit(slot, dB);

  const M_A = bondToken(P.fromHex(m.poll(dA.tag)[0]), A.scalar);
  const M_B = bondToken(P.fromHex(m.poll(dB.tag)[0]), B.scalar);
  m.confirm(dA.tag, bondConfirm(M_A, dA.tag));
  m.confirm(dB.tag, bondConfirm(M_B, dB.tag));

  const aIn = m.pollConfirm(dA.tag)[0];
  const bIn = m.pollConfirm(dB.tag)[0];
  assert.ok(mutualConfirmed(M_A, aIn.confirm, aIn.fromTag), 'A lights');
  assert.ok(mutualConfirmed(M_B, bIn.confirm, bIn.fromTag), 'B lights');
});

test('GARBAGE-PROBE: M disagree ⇒ NEITHER lights', () => {
  const d = Array.from({ length: 6 }, mintIdentity);
  const ring = d.map((x) => x.pubkey);
  const A = d[2], B = d[5], epoch = 2960;
  const m = new BeaconMatcher(ring);
  const s = deriveSharedSecret(A.sk, B.pk);
  const slot = slotId(s, epoch);
  const H = bondBase(s, epoch);
  const dA = dep(ring, 2, A.scalar, slot, depositShare(H, A.scalar).toHex());
  const garbage = beaconPubkey(identityScalar(ed25519.utils.randomSecretKey())).toHex();
  const dB = dep(ring, 5, B.scalar, slot, garbage);
  m.deposit(slot, dA); m.deposit(slot, dB);

  const M_A = bondToken(P.fromHex(m.poll(dA.tag)[0]), A.scalar); // from garbage
  const M_B = bondToken(P.fromHex(m.poll(dB.tag)[0]), B.scalar); // real
  m.confirm(dA.tag, bondConfirm(M_A, dA.tag));
  m.confirm(dB.tag, bondConfirm(M_B, dB.tag));

  const aIn = m.pollConfirm(dA.tag)[0];
  const bIn = m.pollConfirm(dB.tag)[0];
  assert.ok(!mutualConfirmed(M_A, aIn.confirm, aIn.fromTag), 'A does NOT light');
  assert.ok(!mutualConfirmed(M_B, bIn.confirm, bIn.fromTag), 'B (prober) cannot light');
});

test('REFLECTION: B mirrors A\'s confirm ⇒ bound to A\'s tag ⇒ A does NOT light', () => {
  const d = Array.from({ length: 6 }, mintIdentity);
  const ring = d.map((x) => x.pubkey);
  const A = d[0], B = d[3], epoch = 2960;
  const m = new BeaconMatcher(ring);
  const s = deriveSharedSecret(A.sk, B.pk);
  const slot = slotId(s, epoch);
  const H = bondBase(s, epoch);

  // A genuinely deposits toward B (one-way trust). B garbage-probes.
  const dA = dep(ring, 0, A.scalar, slot, depositShare(H, A.scalar).toHex());
  const dB = dep(ring, 3, B.scalar, slot, beaconPubkey(identityScalar(ed25519.utils.randomSecretKey())).toHex());
  m.deposit(slot, dA); m.deposit(slot, dB);

  const M_A = bondToken(P.fromHex(m.poll(dA.tag)[0]), A.scalar);

  // A posts its (tag-bound) confirm → delivered to B's box.
  m.confirm(dA.tag, bondConfirm(M_A, dA.tag));

  // B reads A's confirm value and REFLECTS it back as B's own confirm.
  const stolen = m.pollConfirm(dB.tag)[0];
  assert.equal(stolen.fromTag, dA.tag, 'B sees A\'s confirm (bound to A\'s tag)');
  m.confirm(dB.tag, stolen.confirm); // reflect A's confirm verbatim

  // A polls: the reflected confirm arrives with fromTag = B's tag, but its value is bound to A's tag.
  const aIn = m.pollConfirm(dA.tag)[0];
  assert.equal(aIn.fromTag, dB.tag);
  assert.ok(!mutualConfirmed(M_A, aIn.confirm, aIn.fromTag), 'reflected confirm (A-tag-bound, B-tag-claimed) ⇒ A does NOT light');
});

test('no confirm channel pre-match', () => {
  const d = Array.from({ length: 4 }, mintIdentity);
  const ring = d.map((x) => x.pubkey);
  const m = new BeaconMatcher(ring);
  const slot = slotId(deriveSharedSecret(d[0].sk, d[1].pk), 2960);
  const l = ringSign(ring, 0, d[0].scalar, slot, BEACON_MSG);
  m.deposit(slot, { tag: l.tag, share: d[0].pubkey.toHex(), lrs: l });
  assert.ok(!m.confirm(l.tag, 'abc').relayed, 'confirm rejected before a match exists');
});
