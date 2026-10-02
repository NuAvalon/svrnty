// src/lib/crypto/distress-cadence.ts
/**
 * Distress cadence + fan-out jitter — the TIMING half of the #558 keystone K3 §8 silence invariant.
 *
 * K2's uniform frame (uniform-frame.ts) removes the TYPE and SIZE fingerprints of a distress cry. But Flint's
 * §8 analysis (KB#91383) is explicit that type/size opacity is necessary, NOT sufficient: the TIMING of an
 * emit leaks too. Two timing fingerprints, two planners here — each proven adversarially in
 * distress-cadence.test.ts (refuting "a watcher CANNOT detect the cry", not "the planner emits on a clock"):
 *
 *   (b) SILENCE-UNDER-NON-EVENT.  A cry emitted ONLY when something happens is a burst-after-silence. For a
 *       zero-real-traffic user — plausibly the highest-risk DV population — that burst IS the distress signal,
 *       even if its bytes are perfectly opaque. Per-user-adaptive cover self-classifies ("has cover" ≈ "high
 *       risk"). So the resolution (Flint, spec §8b) is a UNIFORM baseline cover cadence for ALL users: every
 *       user emits one opaque constant-size cell per slot at a steady low rate, forever, whether or not they
 *       have anything to say. A real cry then RIDES a scheduled slot (a cover→distress swap at the device,
 *       invisible on the wire) instead of creating a new event. ── planCoverCadence + scheduleCryIntoCadence.
 *
 *   (c) FAN-OUT FINGERPRINT.  A synchronized N-way fan-out to N guardian satellites at one instant reads as
 *       "broadcast to N endpoints = probable distress". The fan-out must be STAGGERED (jittered) so it matches
 *       ordinary multi-contact cadence rather than a simultaneous burst. ── planFanoutJitter.
 *
 * ★ HONEST TRADEOFF (do-no-harm, flagged to Flint as a threat-model decision — NOT silently baked): riding the
 * next cover slot adds up to ONE PERIOD of latency to a LIFE-SAFETY signal. Silence and urgency are in genuine
 * tension. This module does NOT resolve that tension — it exposes the period as a tunable (like uniform-frame's
 * FRAME_BYTES and route-ratchet's ROUTE_WINDOW_SECONDS) and states the latency bound plainly. A shorter period
 * ⇒ lower worst-case latency but more cover overhead for every user forever. The right value is a measurement /
 * threat-model call for Flint + Peter, and the strong "the cry is undetectable" copy is HELD until that value
 * is set AND the cadence is verified running on the deployed edge (gate-2, Hypatia life-safety APEX KB#91416).
 *
 * ★ PURE PLANNERS, WIRING DEFERRED. These are deterministic given an injected `random` — no timers, no
 * network, no clock read. That is deliberate: it makes the silence PROPERTIES adversarially testable in
 * isolation. The EMIT-PATH that actually drives real timers, holds the per-guardian K1 route-ratchet state,
 * and deposits cells to the satellite is a separate reviewable unit (gated on Flint §8-DEPLOYED + Athena's
 * satellite) — same discipline as K0 deferring satellite-serve and K1 deferring Family-B wiring.
 *
 * NO crypto here — this is scheduling arithmetic. Confidentiality/opacity is the K0 seal + the uniform frame.
 */

/** A source of uniform floats in [0, 1). Injectable for deterministic tests; defaults to a CSPRNG. */
export type Random = () => number;

/** Default CSPRNG-backed uniform in [0, 1) — jitter is not security-critical, but we avoid a global PRNG. */
const cryptoRandom: Random = () => {
  const u32 = crypto.getRandomValues(new Uint32Array(1))[0];
  return u32 / 0x1_0000_0000; // [0, 1)
};

export interface CoverCadenceOpts {
  /** Window start (ms, absolute or relative — the planner is unit-agnostic as long as callers are consistent). */
  startMs: number;
  /** How far ahead to schedule slots (ms). Slots are emitted for [startMs, startMs + windowMs]. */
  windowMs: number;
  /** The UNIFORM baseline period between slots (ms). The one knob that trades worst-case cry latency vs cover
   *  overhead. MUST be > 0. Same value for all users (uniform cadence ⇒ no per-user self-classification). */
  periodMs: number;
  /** Max intra-slot jitter (ms), in [0, periodMs). A perfect metronome is itself a (weak) fingerprint; a small
   *  bounded jitter breaks exact periodicity WITHOUT reordering slots. Default 0 (pure period). */
  jitterMs?: number;
  random?: Random;
}

/**
 * Plan the UNIFORM baseline cover cadence: one emit slot per period across the window, with optional bounded
 * intra-slot jitter. CRUCIALLY this is a function of (start, window, period) ONLY — it does NOT depend on
 * whether the user has a real cry to send. That traffic-independence is the whole §8(b) property: a
 * zero-real-traffic user and an active user emit the SAME cadence, so a cry can hide in it.
 *
 * @returns strictly increasing emit timestamps (ms). Slot i is at startMs + i*periodMs + jitter_i, and the
 *          jitter is bounded below the period so slots never reorder.
 */
export function planCoverCadence(opts: CoverCadenceOpts): number[] {
  const { startMs, windowMs, periodMs } = opts;
  const jitterMs = opts.jitterMs ?? 0;
  const random = opts.random ?? cryptoRandom;
  if (!Number.isFinite(startMs)) throw new Error('cadence: startMs must be finite');
  if (!(periodMs > 0) || !Number.isFinite(periodMs)) throw new Error('cadence: periodMs must be > 0');
  if (!(windowMs >= 0) || !Number.isFinite(windowMs)) throw new Error('cadence: windowMs must be >= 0');
  if (!(jitterMs >= 0) || jitterMs >= periodMs) throw new Error('cadence: jitterMs must be in [0, periodMs)');

  const slots: number[] = [];
  const count = Math.floor(windowMs / periodMs) + 1;
  for (let i = 0; i < count; i++) {
    const base = startMs + i * periodMs;
    const jitter = jitterMs > 0 ? random() * jitterMs : 0;
    slots.push(base + jitter);
  }
  return slots;
}

/**
 * Schedule a real cry to RIDE the baseline cadence: return the first slot at or after `cryAtMs`. The emit-path
 * emits a `'distress'` cell at that slot INSTEAD of the `'cover'` cell it would otherwise have emitted — a
 * cover→distress swap. On the wire the emit happens at a scheduled cadence slot, identical to every other slot,
 * so the cry adds NO new observable event (the §8(b) guarantee). The worst-case added latency is one period.
 *
 * @returns the slot timestamp the cry emits at, or null if no slot at/after cryAtMs exists in `slots`
 *          (the caller must extend the cadence horizon — a cry must never be dropped nor emitted off-cadence).
 */
export function scheduleCryIntoCadence(cryAtMs: number, slots: number[]): number | null {
  if (!Number.isFinite(cryAtMs)) throw new Error('cadence: cryAtMs must be finite');
  for (const slot of slots) {
    if (slot >= cryAtMs) return slot;
  }
  return null;
}

export interface FanoutJitterOpts {
  /** Number of guardians the cry fans out to (>= 1). */
  guardianCount: number;
  /** Earliest emit offset (ms). */
  baseMs: number;
  /** Total stagger window (ms, >= 0) across which the guardian emits are spread. */
  spreadMs: number;
  random?: Random;
}

/**
 * Plan a STAGGERED fan-out: distinct emit offsets for the N guardians, spread across [baseMs, baseMs+spreadMs],
 * so the fan-out does NOT present as a synchronized N-way burst (§8(c)). Each guardian gets its own sub-slot
 * [baseMs + i*spread/N, baseMs + (i+1)*spread/N) with uniform jitter inside it. For N > 1 this guarantees the
 * offsets are distinct and spread (not all equal) PROVIDED spreadMs > 0 — a zero spread would collapse every
 * sub-slot to baseMs (a synchronized burst), so it is REJECTED by construction (see @throws), not silently
 * returned. For N = 1 there is no fan-out fingerprint, so the single offset is simply baseMs (spreadMs ignored).
 *
 * @returns an array of `guardianCount` emit offsets (ms), one per guardian, in sub-slot order.
 * @throws if guardianCount < 1, baseMs non-finite, spreadMs < 0, or (guardianCount > 1 and spreadMs == 0).
 */
export function planFanoutJitter(opts: FanoutJitterOpts): number[] {
  const { guardianCount, baseMs, spreadMs } = opts;
  const random = opts.random ?? cryptoRandom;
  if (!Number.isInteger(guardianCount) || guardianCount < 1) throw new Error('cadence: guardianCount must be >= 1');
  if (!Number.isFinite(baseMs)) throw new Error('cadence: baseMs must be finite');
  if (!(spreadMs >= 0) || !Number.isFinite(spreadMs)) throw new Error('cadence: spreadMs must be >= 0');

  if (guardianCount === 1) return [baseMs];

  // N > 1: spreadMs = 0 collapses every sub-slot width to 0, so all offsets equal baseMs — a synchronized
  // N-way burst, the exact §8(c) fingerprint this planner exists to prevent. Make that unrepresentable
  // (mirror planCoverCadence's periodMs > 0 guard) rather than return a burst that violates the contract.
  // The ADEQUATE spread magnitude (enough to pass as ordinary multi-contact cadence) is a threat-model /
  // measurement call for the emit-path + Flint/Peter — same tier as periodMs — so it is NOT hardcoded here;
  // only the degenerate zero is rejected.
  if (!(spreadMs > 0)) throw new Error('cadence: spreadMs must be > 0 when guardianCount > 1 (spreadMs=0 collapses to a synchronized N-way burst)');

  const sub = spreadMs / guardianCount;
  const offsets: number[] = [];
  for (let i = 0; i < guardianCount; i++) {
    offsets.push(baseMs + i * sub + random() * sub);
  }
  return offsets;
}
