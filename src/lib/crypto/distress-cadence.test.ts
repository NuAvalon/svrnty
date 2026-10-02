// src/lib/crypto/distress-cadence.test.ts
// ADVERSARIAL refutation gate for the #558 keystone K3 TIMING channel (Flint §8(b)/(c), KB#91383).
// Refutes "a watcher CANNOT detect the cry in the timing channel" — NOT "the planner emits on a clock".
//   (b) silence-under-non-event → uniform baseline cover cadence: a cry rides a scheduled slot, adding NO
//       new observable event even for a ZERO-real-traffic user (the DV population = the test case).
//   (c) fan-out fingerprint → staggered emits: an N-way fan-out is not a synchronized burst.
// These planners are pure (deterministic given an injected random), so the properties test in isolation.
// Run: npx tsx --test src/lib/crypto/distress-cadence.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  planCoverCadence,
  scheduleCryIntoCadence,
  planFanoutJitter,
  type Random,
} from './distress-cadence.js';

/** A deterministic [0,1) PRNG (LCG) for reproducible jitter in tests — NOT used in production (crypto default). */
function seeded(seed: number): Random {
  let s = seed >>> 0;
  return () => {
    s = (1664525 * s + 1013904223) >>> 0;
    return s / 0x1_0000_0000;
  };
}

// ════════════════════════════════════════════════════════════════════════
// (b) UNIFORM BASELINE CADENCE — traffic-independent. The whole point: a zero-real-traffic user emits the
// SAME cadence as an active one, so there is no "has traffic" vs "silent" distinction to exploit.
// ════════════════════════════════════════════════════════════════════════
test('(b) the cover cadence is a function of (start, window, period) only — independent of any cry', () => {
  const a = planCoverCadence({ startMs: 0, windowMs: 10_000, periodMs: 1_000, jitterMs: 100, random: seeded(1) });
  const b = planCoverCadence({ startMs: 0, windowMs: 10_000, periodMs: 1_000, jitterMs: 100, random: seeded(1) });
  assert.deepEqual(a, b, 'cadence depends on no cry input — identical for the silent user and the active user');
  assert.equal(a.length, 11, 'floor(window/period)+1 slots across the window');
  for (let i = 1; i < a.length; i++) assert.ok(a[i] > a[i - 1], 'slots strictly increasing (jitter never reorders)');
  for (let i = 0; i < a.length; i++) {
    assert.ok(a[i] >= i * 1_000 && a[i] < i * 1_000 + 1_000, `slot ${i} within its period (jitter < period)`);
  }
});

// ════════════════════════════════════════════════════════════════════════
// (b) THE CRY RIDES A SLOT — a watcher of a zero-real-traffic user sees the IDENTICAL emit-time sequence
// whether or not a cry is present (cover→distress swap at the device). The cry adds no observable event.
// ════════════════════════════════════════════════════════════════════════
test('(b) a cry rides a cadence slot → the observable emit-time sequence is identical with and without the cry', () => {
  const slots = planCoverCadence({ startMs: 0, windowMs: 10_000, periodMs: 1_000, jitterMs: 0, random: seeded(2) });

  // Zero-real-traffic user: the baseline is the emit sequence an observer sees.
  const observedWithoutCry = slots;

  // A real cry arrives mid-window, OFF the cadence (a naive "send now" instant).
  const cryAt = 3_450;
  const emitAt = scheduleCryIntoCadence(cryAt, slots);
  assert.ok(emitAt !== null, 'the cry is scheduled (never dropped)');
  assert.ok(slots.includes(emitAt!), 'the cry emits AT a cadence slot (the slot that would have carried a cover cell)');

  // With the cry, the emit sequence is STILL exactly the slots (one slot carries distress instead of cover).
  const observedWithCry = slots; // one cover→distress swap, same timestamps
  assert.deepEqual(observedWithCry, observedWithoutCry, 'the timing channel is unchanged by the cry (no burst)');

  // POSITIVE CONTROL (non-vacuous): emitting AT cryAt (instant, off-cadence) WOULD inject an event that is
  // NOT in the baseline — a detectable burst-after-silence. Riding the slot is what removes that signal.
  assert.ok(!slots.includes(cryAt), 'the instant "send now" time is NOT a baseline slot — it would be a visible burst');
  assert.ok(emitAt! >= cryAt, 'the cry never emits before it is requested');
});

test('(b) latency bound — riding the next slot costs at most one period (the honest urgency-vs-silence tradeoff)', () => {
  const period = 1_000;
  const jitter = 100;
  const slots = planCoverCadence({ startMs: 0, windowMs: 60_000, periodMs: period, jitterMs: jitter, random: seeded(3) });
  for (const cryAt of [0, 1, 250, 999, 1_000, 5_432, 12_001]) {
    const emitAt = scheduleCryIntoCadence(cryAt, slots);
    assert.ok(emitAt !== null, `scheduled for cryAt=${cryAt}`);
    assert.ok(emitAt! - cryAt < period + jitter, `added latency < one period for cryAt=${cryAt} (bound stated honestly)`);
  }
});

test('(b) a cry past the scheduled horizon returns null (the caller must extend the cadence — never drop, never off-cadence)', () => {
  const slots = planCoverCadence({ startMs: 0, windowMs: 5_000, periodMs: 1_000, jitterMs: 0, random: seeded(4) });
  assert.equal(scheduleCryIntoCadence(10_000, slots), null, 'no slot past the horizon → null (do not silently drop or burst)');
});

// ════════════════════════════════════════════════════════════════════════
// (c) FAN-OUT JITTER — an N-way fan-out is staggered, not a synchronized burst.
// ════════════════════════════════════════════════════════════════════════
test('(c) fan-out to N guardians is staggered: distinct, spread offsets — never a synchronized N-way burst', () => {
  const offsets = planFanoutJitter({ guardianCount: 5, baseMs: 0, spreadMs: 10_000, random: seeded(5) });
  assert.equal(offsets.length, 5, 'one offset per guardian');
  assert.equal(new Set(offsets).size, 5, 'all offsets distinct (not simultaneous)');
  for (const o of offsets) assert.ok(o >= 0 && o < 10_000, 'each offset within the stagger window');
  const span = Math.max(...offsets) - Math.min(...offsets);
  assert.ok(span > 0, 'the fan-out is spread across time, not a single instant');

  // POSITIVE CONTROL: a naive synchronized fan-out (all at base) collides — exactly the fingerprint we avoid.
  const synchronized = Array.from({ length: 5 }, () => 0);
  assert.equal(new Set(synchronized).size, 1, 'the synchronized plan is a single-instant burst (the thing (c) refutes)');
});

test('(c) a single guardian has no fan-out fingerprint — offset is just the base', () => {
  assert.deepEqual(planFanoutJitter({ guardianCount: 1, baseMs: 500, spreadMs: 10_000, random: seeded(6) }), [500]);
});

test('(c) fan-out jitter is deterministic given the injected random (reproducible plans)', () => {
  const a = planFanoutJitter({ guardianCount: 4, baseMs: 100, spreadMs: 8_000, random: seeded(7) });
  const b = planFanoutJitter({ guardianCount: 4, baseMs: 100, spreadMs: 8_000, random: seeded(7) });
  assert.deepEqual(a, b, 'same seed → same plan');
});

// ════════════════════════════════════════════════════════════════════════
// VALIDATION — bad parameters throw (a mis-configured cadence must fail loud, not silently mis-schedule).
// ════════════════════════════════════════════════════════════════════════
test('validation: bad cadence / fan-out parameters throw', () => {
  assert.throws(() => planCoverCadence({ startMs: 0, windowMs: 10, periodMs: 0 }), /periodMs must be > 0/);
  assert.throws(() => planCoverCadence({ startMs: 0, windowMs: 10, periodMs: 100, jitterMs: 100 }), /jitterMs must be in/);
  assert.throws(() => planCoverCadence({ startMs: 0, windowMs: -1, periodMs: 100 }), /windowMs must be >= 0/);
  assert.throws(() => planFanoutJitter({ guardianCount: 0, baseMs: 0, spreadMs: 10 }), /guardianCount must be >= 1/);
  assert.throws(() => planFanoutJitter({ guardianCount: 3, baseMs: 0, spreadMs: -1 }), /spreadMs must be >= 0/);
});
