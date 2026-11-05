// src/lib/crypto/beacon-matcher.test.ts
// Run: npx tsx --test src/lib/crypto/beacon-matcher.test.ts
//
// Proves the #588 oblivious matcher (beacon-matcher.ts) — the v2 PIN2/PIN3 server invariants:
//   • match only on two DISTINCT valid ring members at a slot;
//   • LRS-gate (invalid/ tag-mismatched deposits rejected);
//   • PIN2 no-peek — a party cannot detect a counterpart's LONE deposit (closes OP-5 at the slot B knows);
//   • PIN3 atomic dual-delivery on match (both mailboxes filled in one action);
//   • withdraw is INERT post-match (can't un-ring the bell);
//   • idempotent re-deposit (same member/tag isn't a 2nd member);
//   • probe-oracle resistance — B can only learn A deposited by depositing, which delivers to A too.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ristretto255 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, randomBytes } from '@noble/curves/utils.js';
import { beaconPubkey, ringSign } from './beacon-lrs';
import { BeaconMatcher, BEACON_MSG, type BeaconDeposit } from './beacon-matcher';

const enc = (s: string) => new TextEncoder().encode(s);
function member() {
  const scalar = ristretto255.Point.Fn.create(bytesToNumberLE(randomBytes(64)));
  return { scalar, pubkey: beaconPubkey(scalar) };
}
function directory(n: number) {
  return Array.from({ length: n }, () => member());
}
/** Build a valid deposit for ring member `idx` at `slot`. */
function deposit(ring: ReturnType<typeof beaconPubkey>[], dir: ReturnType<typeof member>[], idx: number, slot: Uint8Array): BeaconDeposit {
  const lrs = ringSign(ring, idx, dir[idx].scalar, slot, BEACON_MSG);
  // share content is opaque to the matcher; use the member's pubkey as a stand-in point.
  return { tag: lrs.tag, share: dir[idx].pubkey.toHex(), lrs };
}

test('match: two distinct members → atomic dual-delivery; each polls its own tag', () => {
  const dir = directory(6);
  const ring = dir.map((m) => m.pubkey);
  const m = new BeaconMatcher(ring);
  const slot = enc('pair-slot-H_e-2960');
  const depA = deposit(ring, dir, 1, slot);
  const depB = deposit(ring, dir, 4, slot);

  const r1 = m.deposit(slot, depA);
  assert.ok(r1.accepted && !r1.matched, "A's lone deposit accepted, no match yet");
  // PIN2 / OP-5: B (not yet deposited) cannot detect A's lone deposit.
  assert.deepEqual(m.poll(depB.tag), [], 'no counterpart detection before B deposits');

  const r2 = m.deposit(slot, depB);
  assert.ok(r2.accepted && r2.matched, "B's deposit completes the match");
  // PIN3: both mailboxes filled atomically — each gets the OTHER's share.
  assert.deepEqual(m.poll(depA.tag), [depB.share], 'A receives B\'s share');
  assert.deepEqual(m.poll(depB.tag), [depA.share], 'B receives A\'s share');
});

test('LRS-gate: invalid ring signature is rejected', () => {
  const dir = directory(4);
  const ring = dir.map((m) => m.pubkey);
  const m = new BeaconMatcher(ring);
  const slot = enc('slot');
  const dep = deposit(ring, dir, 0, slot);
  // tamper a response
  const bad: BeaconDeposit = { ...dep, lrs: { ...dep.lrs, s: dep.lrs.s.map((x, i) => (i === 0 ? x + BigInt(1) : x)) } };
  const r = m.deposit(slot, bad);
  assert.ok(!r.accepted, 'tampered ring signature rejected');
});

test('tag/signature binding: a share under a mismatched tag is rejected', () => {
  const dir = directory(4);
  const ring = dir.map((m) => m.pubkey);
  const m = new BeaconMatcher(ring);
  const slot = enc('slot');
  const dep = deposit(ring, dir, 0, slot);
  const r = m.deposit(slot, { ...dep, tag: 'deadbeef' + dep.tag.slice(8) });
  assert.ok(!r.accepted, 'tag not matching the signature tag is rejected');
});

test('idempotent: same member re-depositing is not a second member', () => {
  const dir = directory(5);
  const ring = dir.map((m) => m.pubkey);
  const m = new BeaconMatcher(ring);
  const slot = enc('slot');
  const depA = deposit(ring, dir, 2, slot);
  m.deposit(slot, depA);
  const again = m.deposit(slot, depA);
  assert.ok(again.accepted && !again.matched, 'same tag twice ⇒ no false match');
  assert.deepEqual(m.poll(depA.tag), [], 'no delivery from a self re-deposit');
});

test('withdraw: works pre-match, INERT post-match', () => {
  const dir = directory(5);
  const ring = dir.map((m) => m.pubkey);
  const slot = enc('slot');

  // pre-match withdraw removes the deposit
  const m1 = new BeaconMatcher(ring);
  const depA = deposit(ring, dir, 1, slot);
  m1.deposit(slot, depA);
  assert.ok(m1.withdraw(slot, depA.tag).withdrawn, 'pre-match withdraw succeeds');
  const depB = deposit(ring, dir, 3, slot);
  const r = m1.deposit(slot, depB);
  assert.ok(!r.matched, 'after A withdrew, B alone does not match');

  // post-match withdraw is inert
  const m2 = new BeaconMatcher(ring);
  m2.deposit(slot, depA);
  m2.deposit(slot, depB); // match
  assert.ok(!m2.withdraw(slot, depA.tag).withdrawn, 'post-match withdraw is inert');
});

test('probe-oracle: B can only learn A deposited by depositing — which delivers to A too', () => {
  const dir = directory(6);
  const ring = dir.map((m) => m.pubkey);
  const m = new BeaconMatcher(ring);
  const slot = enc('slot');
  const depA = deposit(ring, dir, 0, slot);
  const depB = deposit(ring, dir, 5, slot);

  m.deposit(slot, depA); // A's lone deposit
  assert.deepEqual(m.poll(depB.tag), [], 'B cannot detect A without depositing');

  m.deposit(slot, depB); // B "probes" by depositing → match fires
  assert.deepEqual(m.poll(depB.tag), [depA.share], 'B learns (gets A share)...');
  assert.deepEqual(m.poll(depA.tag), [depB.share], '...but A simultaneously learned (got B share)');

  // B tries to retract — too late, A already holds B's share.
  assert.ok(!m.withdraw(slot, depB.tag).withdrawn, "B's post-match withdraw is inert");
  assert.deepEqual(m.poll(depA.tag), [depB.share], "A still holds B's share after B's withdraw attempt");
});
