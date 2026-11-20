// src/lib/crypto/beacon-lrs.test.ts
// Run: npx tsx --test src/lib/crypto/beacon-lrs.test.ts
//
// Proves the #588 beacon LSAG layer (beacon-lrs.ts, SIGNAL-1):
//   • completeness — a genuine ring member's signature verifies;
//   • soundness — a non-member (or tampered sig) fails;
//   • linkability — same signer + same slot ⇒ same tag (server catches double-deposit / "distinct members");
//   • cross-slot unlinkability — same signer, different slot ⇒ different tag (R2);
//   • distinctness — two different signers ⇒ different tags;
//   • anonymity sanity — any ring index produces a verifying signature (indistinguishable membership).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ristretto255 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, randomBytes } from '@noble/curves/utils.js';
import { beaconPubkey, ringSign, ringVerify, tagsLink } from './beacon-lrs';

const L = ristretto255.Point.Fn.ORDER;
const enc = (s: string) => new TextEncoder().encode(s);

function member() {
  const scalar = ristretto255.Point.Fn.create(bytesToNumberLE(randomBytes(64)));
  return { scalar, pubkey: beaconPubkey(scalar) };
}

function directory(n: number) {
  return Array.from({ length: n }, () => member());
}

test('completeness: a genuine member signature verifies', () => {
  const dir = directory(5);
  const ring = dir.map((m) => m.pubkey);
  const slot = enc('H_e-slot-epoch-2960');
  const msg = enc('beacon-deposit');

  const signer = 2;
  const sig = ringSign(ring, signer, dir[signer].scalar, slot, msg);
  assert.ok(ringVerify(ring, slot, msg, sig), 'valid ring signature must verify');
});

test('anonymity sanity: ANY ring index produces a verifying signature', () => {
  const dir = directory(4);
  const ring = dir.map((m) => m.pubkey);
  const slot = enc('slot-X');
  const msg = enc('m');
  for (let i = 0; i < dir.length; i++) {
    const sig = ringSign(ring, i, dir[i].scalar, slot, msg);
    assert.ok(ringVerify(ring, slot, msg, sig), `signer index ${i} must verify`);
  }
});

test('soundness: a non-member cannot forge', () => {
  const dir = directory(5);
  const ring = dir.map((m) => m.pubkey);
  const slot = enc('slot');
  const msg = enc('m');
  // outsider's scalar does NOT correspond to ring[1] → ring won't close.
  const outsider = member();
  const sig = ringSign(ring, 1, outsider.scalar, slot, msg);
  assert.ok(!ringVerify(ring, slot, msg, sig), 'forged signature (wrong secret) must NOT verify');
});

test('soundness: a tampered response is rejected', () => {
  const dir = directory(4);
  const ring = dir.map((m) => m.pubkey);
  const slot = enc('slot');
  const msg = enc('m');
  const sig = ringSign(ring, 0, dir[0].scalar, slot, msg);
  const tampered = { ...sig, s: [...sig.s] };
  tampered.s[1] = (tampered.s[1] + BigInt(1)) % L;
  assert.ok(!ringVerify(ring, slot, msg, tampered), 'tampered response must NOT verify');
});

test('linkability: same signer + same slot ⇒ same tag (across different messages)', () => {
  const dir = directory(5);
  const ring = dir.map((m) => m.pubkey);
  const slot = enc('slot-epoch-2960');
  const a = ringSign(ring, 3, dir[3].scalar, slot, enc('msg-1'));
  const b = ringSign(ring, 3, dir[3].scalar, slot, enc('msg-2'));
  assert.ok(tagsLink(a, b), 'same signer+slot must link (double-deposit detectable)');
});

test('cross-slot unlinkability: same signer, different slot ⇒ different tag', () => {
  const dir = directory(5);
  const ring = dir.map((m) => m.pubkey);
  const a = ringSign(ring, 3, dir[3].scalar, enc('slot-epoch-2960'), enc('m'));
  const b = ringSign(ring, 3, dir[3].scalar, enc('slot-epoch-2961'), enc('m'));
  assert.ok(!tagsLink(a, b), 'different slot ⇒ different tag ⇒ cross-epoch unlinkable');
});

test('distinctness: two different signers ⇒ different tags (server sees two distinct members)', () => {
  const dir = directory(5);
  const ring = dir.map((m) => m.pubkey);
  const slot = enc('slot-epoch-2960');
  const a = ringSign(ring, 1, dir[1].scalar, slot, enc('m'));
  const b = ringSign(ring, 4, dir[4].scalar, slot, enc('m'));
  assert.ok(!tagsLink(a, b), 'distinct signers ⇒ distinct tags');
  assert.ok(ringVerify(ring, slot, enc('m'), a) && ringVerify(ring, slot, enc('m'), b));
});
