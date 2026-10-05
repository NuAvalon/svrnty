// src/lib/trust/held-affirmatives.test.ts
// ADVERSARIAL gate for the piece-2 VIEWER-SIDE reveal AND-gate (task #579, §F3 fail-closed).
// Refutes survivor-safety properties:
//   · §F3 FAIL-CLOSED: an UNREADABLE held store surfaces NOTHING transitive (never surface on a guess),
//   · an EXPIRED affirmative stops surfacing its party (block bites by absence, read-time, no stale window),
//   · the gate is an AND-filter — only fresh-affirmed fps survive (positive control: a fresh one DOES),
//   · an EMPTY held store surfaces nothing (the DARK-until-transport property — safe),
//   · recordAffirmative is monotonic (a replayed older epoch never overwrites).
// Run: npx tsx --test src/lib/trust/held-affirmatives.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  emptyHeld,
  isHeldAffirmatives,
  holdsFreshAffirmative,
  affirmGateCircle,
  gateEdgeTransitiveSets,
  recordAffirmative,
  pruneExpired,
  type HeldAffirmatives,
} from './held-affirmatives.js';

const CAROL = 'c'.repeat(64);
const DAVE = 'd'.repeat(64);
const EVE = 'e'.repeat(64);
const NOW = 1_700_000_000;

function held(entries: Record<string, { validUntil: number; epoch: number }>): HeldAffirmatives {
  return entries;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (§F3 FAIL-CLOSED) — an unreadable (null) held store surfaces NOTHING transitive.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(§F3) null held store ⇒ gate surfaces nothing', () => {
  assert.deepEqual(affirmGateCircle([CAROL, DAVE], null, NOW), [], 'unreadable ⇒ []');
  assert.equal(holdsFreshAffirmative(null, CAROL, NOW), false, 'unreadable ⇒ not fresh');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (EXPIRY by absence) — once an affirmative expires, its party stops surfacing (read-time, no stale window).
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(EXPIRY) an expired affirmative no longer surfaces its party', () => {
  const h = held({ [CAROL]: { validUntil: NOW + 100, epoch: 3 } });
  assert.equal(holdsFreshAffirmative(h, CAROL, NOW), true, 'fresh before expiry');
  assert.equal(holdsFreshAffirmative(h, CAROL, NOW + 100), false, 'at expiry ⇒ hidden');
  assert.equal(holdsFreshAffirmative(h, CAROL, NOW + 500), false, 'past expiry ⇒ hidden');
  assert.deepEqual(affirmGateCircle([CAROL], h, NOW + 100), [], 'gate drops the expired party');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (AND-GATE + POSITIVE CONTROL) — only fps with a FRESH affirmative survive; a fresh one DOES (we don't
// over-hide). This is the disclosed_circle filter at the single projection.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(AND-GATE) filters a disclosed_circle to only fresh-affirmed fps', () => {
  const h = held({
    [CAROL]: { validUntil: NOW + 100, epoch: 1 }, // fresh
    [DAVE]: { validUntil: NOW - 1, epoch: 1 },     // expired
    // EVE: no affirmative held
  });
  assert.deepEqual(affirmGateCircle([CAROL, DAVE, EVE], h, NOW), [CAROL], 'only Carol survives');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (DARK-until-transport) — an EMPTY held store surfaces nothing. Until the receive-path populates held
// affirmatives, the transitive discovery surface is inert — the under-reveal-safe spine property.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(DARK) empty held store surfaces nothing transitive', () => {
  assert.deepEqual(affirmGateCircle([CAROL, DAVE], emptyHeld(), NOW), [], 'no affirmatives ⇒ nothing surfaced');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (MONOTONIC) — recordAffirmative keeps the HIGHER epoch; a replayed older epoch never overwrites a fresher.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(MONOTONIC) recordAffirmative keeps the higher epoch', () => {
  let h = emptyHeld();
  h = recordAffirmative(h, CAROL, { validUntil: NOW + 100, epoch: 5 });
  assert.equal(h[CAROL].epoch, 5);
  // A replayed older (epoch 4, even if it claims a later validUntil) must NOT overwrite.
  h = recordAffirmative(h, CAROL, { validUntil: NOW + 9999, epoch: 4 });
  assert.equal(h[CAROL].epoch, 5, 'older epoch rejected');
  assert.equal(h[CAROL].validUntil, NOW + 100, 'validUntil unchanged by the stale replay');
  // A genuine renewal (epoch 6) updates both.
  h = recordAffirmative(h, CAROL, { validUntil: NOW + 200, epoch: 6 });
  assert.equal(h[CAROL].epoch, 6);
  assert.equal(h[CAROL].validUntil, NOW + 200);
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (EDGE GATE) — gateEdgeTransitiveSets gates disclosed_circle + they_trust at the display boundary, UNIONs
// the metadata fallback then CLEARS metadata.* (so a reader's metadata fallback can't re-admit an ungated
// party), leaves the edge's own identity untouched, and fail-closes on null held.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(EDGE GATE) filters disclosed_circle/they_trust (incl. metadata fallback) and clears metadata.*', () => {
  const edge = {
    peer_fingerprint: 'self',
    trusted: true,
    disclosed_circle: [CAROL, DAVE],              // Carol fresh, Dave expired
    they_trust: [EVE],                            // Eve: no affirmative
    metadata: { disclosed_circle: [EVE], note: 'keep-me' }, // metadata fallback would re-admit Eve
  };
  const h = held({ [CAROL]: { validUntil: NOW + 100, epoch: 1 }, [DAVE]: { validUntil: NOW - 1, epoch: 1 } });
  const [gated] = gateEdgeTransitiveSets([edge], h, NOW);
  assert.deepEqual(gated.disclosed_circle, [CAROL], 'only fresh Carol survives (Dave expired, Eve unaffirmed)');
  assert.deepEqual(gated.they_trust, [], 'Eve has no affirmative ⇒ dropped');
  assert.equal(gated.metadata?.disclosed_circle, undefined, 'metadata.disclosed_circle CLEARED (no bypass)');
  assert.equal((gated.metadata as any)?.note, 'keep-me', 'unrelated metadata preserved');
  assert.equal(gated.peer_fingerprint, 'self', 'edge identity untouched — transitive-only');
  assert.notEqual(gated, edge, 'returns a new object, does not mutate input');
  assert.deepEqual(edge.disclosed_circle, [CAROL, DAVE], 'input edge unmutated');
});

test('(EDGE GATE §F3) null held ⇒ every transitive set empties', () => {
  const edge = { disclosed_circle: [CAROL], they_trust: [DAVE], metadata: { they_trust: [EVE] } };
  const [gated] = gateEdgeTransitiveSets([edge], null, NOW);
  assert.deepEqual(gated.disclosed_circle, [], 'null held ⇒ disclosed empty');
  assert.deepEqual(gated.they_trust, [], 'null held ⇒ they_trust empty');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (EDGE GATE — ALL 3 theyTrustSet SOURCES, Flint §F3 KB#92271) — the gate must filter the THIRD source
// peer_mutual[].peer_fingerprint, not just they_trust + metadata.they_trust. TRIPWIRE: a new theyTrustSet/
// theyKnowSet source added without being added to gateEdgeTransitiveSets must break this. We assert the
// gate's output, THEN the real reader (witnessedPeerChords) sees nothing un-affirmed across all sources.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(EDGE GATE peer_mutual) the third theyTrustSet source is gated too', () => {
  const edge = {
    disclosed_circle: [CAROL],
    they_trust: [DAVE],
    peer_mutual: [{ peer_fingerprint: CAROL }, { peer_fingerprint: DAVE }],
    metadata: { they_trust: [EVE] },
  };
  // Only CAROL affirmed. DAVE expired, EVE absent.
  const h = held({ [CAROL]: { validUntil: NOW + 100, epoch: 1 }, [DAVE]: { validUntil: NOW - 1, epoch: 1 } });
  const [gated] = gateEdgeTransitiveSets([edge], h, NOW);
  assert.deepEqual(gated.peer_mutual, [{ peer_fingerprint: CAROL }], 'peer_mutual filtered to only the affirmed fp (Carol; Dave expired)');
  assert.deepEqual(gated.disclosed_circle, [CAROL], 'disclosed_circle gated (Carol affirmed)');
  assert.deepEqual(gated.they_trust, [], 'they_trust = [Dave]+meta[Eve], neither affirmed ⇒ empty');
  // null held ⇒ peer_mutual empties too (fail-closed across ALL sources).
  const [gatedNull] = gateEdgeTransitiveSets([edge], null, NOW);
  assert.deepEqual(gatedNull.peer_mutual, [], 'null held ⇒ peer_mutual empty (fail-closed, all sources)');
});

// ── shape guard + housekeeping ────────────────────────────────────────────────────────────────────────
test('isHeldAffirmatives rejects malformed maps; pruneExpired drops expired', () => {
  assert.equal(isHeldAffirmatives(null), false);
  assert.equal(isHeldAffirmatives([]), false, 'array is not a held map');
  assert.equal(isHeldAffirmatives({ [CAROL]: { validUntil: 'soon', epoch: 1 } }), false, 'non-number validUntil');
  assert.equal(isHeldAffirmatives({ [CAROL]: { validUntil: NOW, epoch: 1 } }), true);
  const pruned = pruneExpired(held({ [CAROL]: { validUntil: NOW + 100, epoch: 1 }, [DAVE]: { validUntil: NOW - 1, epoch: 1 } }), NOW);
  assert.deepEqual(Object.keys(pruned), [CAROL], 'expired Dave pruned, fresh Carol kept');
});
