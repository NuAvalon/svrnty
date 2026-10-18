// src/lib/crypto/beacon-confirm.test.ts
// Run: npx tsx --test src/lib/crypto/beacon-confirm.test.ts
//
// #588 FINDING-1 fix (Flint hammer #174179): the mandatory bond-confirmation exchange.
// The consistent-M check is only safe if the PROTOCOL forces both parties to exchange H(M) and light
// "mutual" ONLY on agreement — never on "I computed a valid-looking M" alone. This proves:
//   • GENUINE: both derive the same M ⇒ confirmations agree ⇒ BOTH light mutual.
//   • GARBAGE-PROBE: B deposits a garbage share (computes the REAL M_B from A's genuine share, the
//     attack Flint flagged) ⇒ A's M ≠ B's M ⇒ confirmations DISAGREE ⇒ NEITHER side lights mutual.
//   • No confirm channel exists pre-match (the exchange is strictly post-match + paired).

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

test('GENUINE: matching M ⇒ confirmations agree ⇒ BOTH light mutual', () => {
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[1];
  const B = dir[4];
  const epoch = 2960;
  const m = new BeaconMatcher(ring);

  const sAB = deriveSharedSecret(A.sk, B.pk);
  const slot = slotId(sAB, epoch);
  const H = bondBase(sAB, epoch);
  const depA: BeaconDeposit = (() => { const l = ringSign(ring, 1, A.scalar, slot, BEACON_MSG); return { tag: l.tag, share: depositShare(H, A.scalar).toHex(), lrs: l }; })();
  const depB: BeaconDeposit = (() => { const l = ringSign(ring, 4, B.scalar, slot, BEACON_MSG); return { tag: l.tag, share: depositShare(H, B.scalar).toHex(), lrs: l }; })();

  m.deposit(slot, depA);
  m.deposit(slot, depB); // match

  // Each computes its bond M from the delivered counterpart share.
  const M_A = bondToken(P.fromHex(m.poll(depA.tag)[0]), A.scalar);
  const M_B = bondToken(P.fromHex(m.poll(depB.tag)[0]), B.scalar);

  // Mandatory confirmation round, relayed by the matcher.
  m.confirm(depA.tag, bondConfirm(M_A));
  m.confirm(depB.tag, bondConfirm(M_B));

  const aLights = mutualConfirmed(M_A, m.pollConfirm(depA.tag)[0]);
  const bLights = mutualConfirmed(M_B, m.pollConfirm(depB.tag)[0]);
  assert.ok(aLights, 'A lights mutual (peer confirm matches A\'s M)');
  assert.ok(bLights, 'B lights mutual (peer confirm matches B\'s M)');
});

test('GARBAGE-PROBE: B deposits garbage ⇒ M disagree ⇒ NEITHER side lights mutual', () => {
  const dir = Array.from({ length: 6 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const A = dir[2];
  const B = dir[5];
  const epoch = 2960;
  const m = new BeaconMatcher(ring);

  const sAB = deriveSharedSecret(A.sk, B.pk);
  const slot = slotId(sAB, epoch);
  const H = bondBase(sAB, epoch);

  // A genuine.
  const depA: BeaconDeposit = (() => { const l = ringSign(ring, 2, A.scalar, slot, BEACON_MSG); return { tag: l.tag, share: depositShare(H, A.scalar).toHex(), lrs: l }; })();
  m.deposit(slot, depA);

  // B PROBES with a garbage share (valid LRS membership, but not b·H).
  const garbage = beaconPubkey(identityScalar(ed25519.utils.randomSecretKey())).toHex();
  const lrsB = ringSign(ring, 5, B.scalar, slot, BEACON_MSG);
  m.deposit(slot, { tag: lrsB.tag, share: garbage, lrs: lrsB }); // match EVENT fires (symmetric, fine)

  // B computes the REAL M_B from A's genuine share (the attack). A computes M_A from B's garbage.
  const M_B = bondToken(P.fromHex(m.poll(lrsB.tag)[0]), B.scalar); // real
  const M_A = bondToken(P.fromHex(m.poll(depA.tag)[0]), A.scalar); // from garbage

  m.confirm(depA.tag, bondConfirm(M_A));
  m.confirm(lrsB.tag, bondConfirm(M_B));

  // Neither can light mutual: A's M ≠ B's M ⇒ confirmations disagree.
  assert.ok(!mutualConfirmed(M_A, m.pollConfirm(depA.tag)[0]), 'A does NOT light (garbage ⇒ M mismatch)');
  assert.ok(!mutualConfirmed(M_B, m.pollConfirm(lrsB.tag)[0]), 'B (prober) cannot unilaterally light either');
});

test('no confirm channel pre-match', () => {
  const dir = Array.from({ length: 4 }, mintIdentity);
  const ring = dir.map((d) => d.pubkey);
  const m = new BeaconMatcher(ring);
  const slot = slotId(deriveSharedSecret(dir[0].sk, dir[1].pk), 2960);
  const l = ringSign(ring, 0, dir[0].scalar, slot, BEACON_MSG);
  m.deposit(slot, { tag: l.tag, share: dir[0].pubkey.toHex(), lrs: l });
  assert.ok(!m.confirm(l.tag, 'abc').relayed, 'confirm is rejected before a match exists');
});
