// src/lib/crypto/route-ratchet.test.ts
// ADVERSARIAL refutation gate for the #558 keystone K1 route ratchet (§5).
// Each of the four core tests refutes a PROTECT-THE-PERSON property — "an adversary who [X] CANNOT [Y]" —
// not the adjacent mechanic ("the ratchet advances"). That framing is the keystone build-norm (Archie,
// Flint KB#91387); a green that only proves advancement would flatter the property, not verify it (K0-1 scar).
// Run: npx tsx --test src/lib/crypto/route-ratchet.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { deriveSharedSecret } from './mutual-trust.js';
import {
  RouteRatchet,
  directionTag,
  currentWindowIndex,
  deriveRootRatchetKey,
  advanceRatchetKey,
  deriveRouteId,
  rekeyRootSecret,
  ROUTE_WINDOW_SECONDS,
  type Direction,
} from './route-ratchet.js';

// ── test fixtures ───────────────────────────────────────────────────────
const fill = (b: number, n = 32) => new Uint8Array(n).fill(b);

// Two identities A, B. s_AB is the symmetric pairwise handshake secret (the ratchet root).
const seedA = fill(0x11);
const seedB = fill(0x22);
const pubA = ed25519.getPublicKey(seedA);
const pubB = ed25519.getPublicKey(seedB);
const fpA = bytesToHex(pubA);
const fpB = bytesToHex(pubB);
const s_AB = deriveSharedSecret(seedA, pubB); // A's view
const s_BA = deriveSharedSecret(seedB, pubA); // B's view — must equal s_AB (symmetric DH)

const DIR_AB: Direction = directionTag(fpA, fpB); // A→B chain
const ANCHOR = 480_000; // an arbitrary pairing window (absolute)

/** From-genesis oracle: the ground-truth route_id at any window, keeping the whole chain (what a ratchet
 *  must NOT do). Used to check correctness AND to feed old route_ids to the adversary in the FS test. */
function oracleRouteId(rootSecret: Uint8Array, dir: Direction, anchor: number, target: number): string {
  let rk = deriveRootRatchetKey(rootSecret, dir);
  for (let w = anchor + 1; w <= target; w++) rk = advanceRatchetKey(rk, w);
  return deriveRouteId(rk);
}

// ── sanity: DH symmetry + fast-forward == incremental (the ratchet computes the oracle's values) ─────────
test('sanity: s_AB is symmetric and RouteRatchet reproduces the from-genesis oracle', () => {
  assert.equal(bytesToHex(s_AB), bytesToHex(s_BA), 'DH shared secret must be symmetric');
  for (const w of [ANCHOR, ANCHOR + 1, ANCHOR + 7, ANCHOR + 100]) {
    const r = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, w);
    assert.equal(r.currentRouteId(), oracleRouteId(s_AB, DIR_AB, ANCHOR, w), `route_id(${w}) matches oracle`);
    assert.equal(r.currentRouteId().length, 32, 'route_id is 16 bytes (32 hex)');
  }
});

// ════════════════════════════════════════════════════════════════════════
// (1) UNLINKABILITY — the keystone's point.
// Adversary who holds route_id(W) and route_id(W+k) for the SAME pair CANNOT tell they are the same pair,
// and CANNOT derive one from the other, without the rk chain.
// ════════════════════════════════════════════════════════════════════════
test('(1) UNLINKABILITY: an observer with two route_ids of the same pair cannot link them (only rk can)', () => {
  const W = ANCHOR + 50;
  const K = 9;
  const idW = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W).currentRouteId();
  const idWk = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W + K).currentRouteId();

  // Rotation: the two windows of the SAME pair share no equality → cannot be linked by matching.
  assert.notEqual(idW, idWk, 'same-pair route_ids rotate across windows (unlinkable by equality)');

  // No cross-pair collision: a DIFFERENT pair at the same window is a different tag.
  const seedC = fill(0x33);
  const pubC = ed25519.getPublicKey(seedC);
  const s_AC = deriveSharedSecret(seedA, pubC);
  const dirAC = directionTag(fpA, bytesToHex(pubC));
  const idAC = RouteRatchet.init(s_AC, dirAC, ANCHOR, W).currentRouteId();
  assert.notEqual(idW, idAC, 'different pairs produce different route_ids at the same window');

  // No linkable structure across a whole sweep of the pair's windows: all distinct (a repeat would be a
  // stable per-pair signal a relay could cluster on). 200 consecutive windows, zero collisions.
  const seen = new Set<string>();
  for (let w = W; w < W + 200; w++) seen.add(oracleRouteId(s_AB, DIR_AB, ANCHOR, w));
  assert.equal(seen.size, 200, 'route_ids across 200 windows are all distinct — no per-pair stable signal');

  // POSITIVE CONTROL — the link is recoverable WITH the rk chain (proving unlinkability is exactly
  // "without the secret"): an authorized holder of s_AB re-derives both ids and confirms the same chain.
  assert.equal(oracleRouteId(s_AB, DIR_AB, ANCHOR, W), idW, 's_AB holder can re-derive route_id(W)');
  assert.equal(oracleRouteId(s_AB, DIR_AB, ANCHOR, W + K), idWk, 's_AB holder can re-derive route_id(W+k)');
});

// ════════════════════════════════════════════════════════════════════════
// (2) FORWARD-SECRECY (retro-linkage, §5-A) + edge-window tight bound (§5-B).
// Adversary who SEIZES the ratchet state at window W CANNOT recompute route_id for ANY window < W-1.
// The state retains ONLY the route_id(W-1) MATCHER (one-way), never rk_{W-1}.
// ════════════════════════════════════════════════════════════════════════
test('(2) FORWARD-SECRECY: seized state at W cannot reach any window before the W-1 edge matcher', () => {
  const W = ANCHOR + 40;
  const seized = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W); // this IS the post-advance retained state

  // Reachable from the seized state = exactly {W-1 (retained matcher), W, W+1 (derived on demand)}.
  assert.ok(seized.matches(oracleRouteId(s_AB, DIR_AB, ANCHOR, W - 1)), 'W-1 matches (edge matcher)');
  assert.ok(seized.matches(oracleRouteId(s_AB, DIR_AB, ANCHOR, W)), 'W matches (current)');
  assert.ok(seized.matches(oracleRouteId(s_AB, DIR_AB, ANCHOR, W + 1)), 'W+1 matches (derived on demand)');

  // FS: every window strictly before the edge (W-2 and earlier) is UNREACHABLE — the seized state cannot
  // recognize or derive those route_ids. rk_{W-1} would recompute all of window W-1 forward; it is NOT kept,
  // only the terminal route_id(W-1) matcher is → the pre-edge history is one-way-severed.
  for (let w = ANCHOR; w <= W - 2; w++) {
    assert.equal(
      seized.matches(oracleRouteId(s_AB, DIR_AB, ANCHOR, w)),
      false,
      `window ${w} (< W-1) is unrecoverable from the seized state`,
    );
  }

  // The edge matcher is NOT rk_{W-1}: it is the 16-byte route_id(W-1) (32 hex), a one-way terminal value.
  // Advancing past the edge DROPS it — after moving to W+1, window W-1 is no longer matchable (tight bound:
  // never more than one previous window of linkable history, and it decays forward).
  seized.advanceTo(W + 1);
  assert.equal(
    seized.matches(oracleRouteId(s_AB, DIR_AB, ANCHOR, W - 1)),
    false,
    'after advancing to W+1, the old W-1 matcher is dropped (no accumulating history)',
  );
  assert.ok(seized.matches(oracleRouteId(s_AB, DIR_AB, ANCHOR, W)), 'the new edge matcher is now W (was current)');

  // CLAIM BOUNDARY (do-no-harm): FS requires s_AB is NOT co-resident. Prove the ratchet does not retain it —
  // zeroing the original root secret after init does not disturb the ratchet (it copied only rk forward).
  const rootCopy = Uint8Array.from(s_AB);
  const r2 = RouteRatchet.init(rootCopy, DIR_AB, ANCHOR, W);
  rootCopy.fill(0); // simulate discarding s_AB
  assert.equal(r2.currentRouteId(), oracleRouteId(s_AB, DIR_AB, ANCHOR, W), 'ratchet works without retained s_AB');
});

// ════════════════════════════════════════════════════════════════════════
// (3) POST-COMPROMISE SECURITY (§5-A PCS gap; my v1 call for device-seizure / DV pop).
// After a coarse DH re-key, an adversary who seized PRE-rekey state CANNOT derive post-rekey route_ids.
// Modeled with the STRONGEST adversary — one who holds the full old root s_AB (a-fortiori over rk_W seizure).
// ════════════════════════════════════════════════════════════════════════
test('(3) PCS: an adversary holding pre-rekey state cannot follow the chain past a fresh-DH re-key', () => {
  const W = ANCHOR + 30;
  const NOW = W + 3;

  // Legit A and B each hold the ratchet at W, then perform a PCS re-key with FRESH ephemeral DH the
  // adversary never observed. Both fold the SAME fresh entropy → they must stay in rendezvous.
  const ephSeedA = fill(0xa1);
  const ephSeedB = fill(0xb2);
  const freshDH_A = deriveSharedSecret(ephSeedA, ed25519.getPublicKey(ephSeedB));
  const freshDH_B = deriveSharedSecret(ephSeedB, ed25519.getPublicKey(ephSeedA));
  assert.equal(bytesToHex(freshDH_A), bytesToHex(freshDH_B), 'fresh ephemeral DH is symmetric');

  const newRoot = rekeyRootSecret(s_AB, freshDH_A);
  const legitA = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W);
  const legitB = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W);
  legitA.rekey(newRoot, W, NOW);
  legitB.rekey(rekeyRootSecret(s_AB, freshDH_B), W, NOW);
  assert.equal(legitA.currentRouteId(), legitB.currentRouteId(), 'both parties rendezvous AFTER the re-key');

  // The adversary continues the SEIZED (old) chain forward — the most it can do without fresh_DH.
  const adversaryContinuesOldChain = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, NOW);
  assert.notEqual(
    legitA.currentRouteId(),
    adversaryContinuesOldChain.currentRouteId(),
    'the seized chain forward does NOT track the re-keyed chain',
  );

  // The adversary cannot RE-KEY into the new chain: it lacks fresh_DH. Any DH it can supply (even a guess,
  // or the old root itself) yields a different root → different route_ids.
  const guessRoot = rekeyRootSecret(s_AB, fill(0xee)); // adversary's best guess ≠ fresh_DH
  const adversaryRekeyGuess = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W);
  adversaryRekeyGuess.rekey(guessRoot, W, NOW);
  assert.notEqual(newRoot.length, 0);
  assert.notEqual(bytesToHex(newRoot), bytesToHex(s_AB), 'the re-keyed root differs from the old root');
  assert.notEqual(
    legitA.currentRouteId(),
    adversaryRekeyGuess.currentRouteId(),
    'a re-key with any DH other than the fresh one cannot reproduce the post-rekey route_ids',
  );
});

// ════════════════════════════════════════════════════════════════════════
// (4) §5-F DETERMINISM (do-no-harm delivery).
// Sender and recipient independently compute the SAME window and route_id with NO shared runtime state;
// a desync is DETECTED (no match), never silently mis-delivered. Two directions never collide.
// ════════════════════════════════════════════════════════════════════════
test('(4) DETERMINISM: window_index is pure time and both sides rendezvous offline', () => {
  // window_index = ⌊now/dur⌋, pure — same wall time → same window, no runtime state.
  assert.equal(currentWindowIndex(0, 3600), 0);
  assert.equal(currentWindowIndex(3600 * 1000 - 1, 3600), 0);
  assert.equal(currentWindowIndex(3600 * 1000, 3600), 1);
  assert.equal(currentWindowIndex(7200 * 1000, 3600), 2);
  assert.equal(ROUTE_WINDOW_SECONDS, 3600);

  const W = ANCHOR + 12;
  // Sender (A) and recipient (B) each build the A→B chain from their OWN copy of the pairwise secret, with
  // no other coordination — and land on the same route_id.
  const sender = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W);
  const recipient = RouteRatchet.init(s_BA, DIR_AB, ANCHOR, W);
  assert.equal(sender.currentRouteId(), recipient.currentRouteId(), 'offline rendezvous holds (no shared state)');
});

test('(4) DETERMINISM: fast-forward equals incremental (dormant party catches up to the same tag)', () => {
  const target = ANCHOR + 25;
  const jumped = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, target); // one big fast-forward
  const stepped = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, ANCHOR);
  for (let w = ANCHOR + 1; w <= target; w++) stepped.advanceTo(w); // window-by-window
  assert.equal(jumped.currentRouteId(), stepped.currentRouteId(), 'dormant fast-forward == incremental advance');
});

test('(4) DETERMINISM: desync is DETECTED (edge tolerated, far miss rejected — never silent mis-delivery)', () => {
  const W = ANCHOR + 20;
  const recipient = RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W);

  // Edge window: a sender one window ahead/behind is still accepted (skew / in-flight boundary).
  assert.ok(recipient.matches(RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W + 1).currentRouteId()), 'W+1 tolerated');
  assert.ok(recipient.matches(RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W - 1).currentRouteId()), 'W-1 tolerated');

  // Far desync: a sender 5 windows off does NOT match → the mismatch is detected, not silently delivered.
  assert.equal(
    recipient.matches(RouteRatchet.init(s_AB, DIR_AB, ANCHOR, W + 5).currentRouteId()),
    false,
    'a far-desynced route_id is rejected (failure detected, not mis-routed)',
  );
});

test('(4) DETERMINISM: the two directions of a pair never collide (A→B ≠ B→A)', () => {
  const W = ANCHOR + 15;
  const ab = RouteRatchet.init(s_AB, directionTag(fpA, fpB), ANCHOR, W).currentRouteId();
  const ba = RouteRatchet.init(s_AB, directionTag(fpB, fpA), ANCHOR, W).currentRouteId();
  assert.notEqual(ab, ba, 'send and reply directions get independent chains');
});

// ── defensive: bad inputs fail loudly, not silently ──────────────────────
test('guards: same-fp direction, backward clock, and empty PCS entropy all throw', () => {
  assert.throws(() => directionTag(fpA, fpA), /must differ/);
  assert.throws(() => RouteRatchet.init(s_AB, DIR_AB, ANCHOR, ANCHOR - 1), /precedes anchorWindow/);
  assert.throws(() => rekeyRootSecret(s_AB, new Uint8Array(0)), /fresh DH entropy/);
});
