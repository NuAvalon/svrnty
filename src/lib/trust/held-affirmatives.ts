// src/lib/trust/held-affirmatives.ts
/**
 * Piece-2 mutual-block — the VIEWER-SIDE held-affirmatives store + the FAIL-CLOSED reveal AND-gate filter
 * (task #579, spec KB#92246, Flint §F seal KB#92252).
 *
 * WHAT IT IS: the affirmatives Anna has RECEIVED — a map {signer durable_id → { validUntil, epoch }}. Anna's
 * client surfaces a TRANSITIVE party P (a mutual-of-mutual, listed in some contact's disclosed_circle /
 * they_trust) IFF Anna holds a FRESH (now < validUntil) affirmative from P. When F stops emitting to Anna
 * (F suppressed her — suppression.ts), F's held affirmative EXPIRES → F drops from Anna's transitive graph,
 * including via a mutual friend (#156420). This is the OTHER half of the pair: suppression.ts is F's emit-side
 * "whom I won't show myself to"; THIS is Anna's viewer-side "who's currently showing themselves to me."
 *
 * ★ SCOPE — TRANSITIVE ONLY: the gate filters disclosed_circle / they_trust (the PSI-discovered mutual-of-
 * mutual sets), NEVER Anna's directly-added contacts. A contact Anna added herself stays in her book
 * regardless of affirmatives; a DIRECT peer going dark is piece-1's job (block≡offline #572 / open_visibility).
 * Piece-2 governs only the DISCOVERY surface — who Anna learns about THROUGH the graph.
 *
 * ★ §F3 FAIL-CLOSED: if the held store is UNREADABLE (null — locked / decrypt-fail / malformed), the gate
 * surfaces NOTHING transitive (returns []). "Can't confirm a fresh affirmative ⇒ don't surface." This
 * under-reveals (safe) — the viewer simply sees no mutual-of-mutual until the store reads cleanly.
 *
 * ★ READ-TIME gate (not persist-time): the filter runs at PROJECTION/display time against the viewer's
 * wall-clock, so an expired affirmative stops surfacing its party WITHIN the TTL with NO staleness window —
 * strictly stronger than a persist-then-sweep (which would surface a just-expired party until the next sweep,
 * and briefly on app-open before a sweep runs). Survivor-safety ⇒ take the strongest fail-closed option.
 *
 * §C FIREWALL: owner-local; the RECEIVED affirmative payloads rode the wire (relay-blind), but this derived
 * held-set is the viewer's private state and never re-serializes outbound.
 */
import { isAffirmFresh } from '../crypto/visible-affirm.js';

export interface HeldAffirmative {
  /** Absolute expiry, unix seconds (from the verified visible-affirm). */
  validUntil: number;
  /** The monotonic epoch of the affirmative we're holding (anti-rollback floor for the next receive). */
  epoch: number;
}

/** Map: signer durable_id (lowercase-hex canonical fingerprint) → the freshest affirmative held from them. */
export type HeldAffirmatives = Record<string, HeldAffirmative>;

export function emptyHeld(): HeldAffirmatives {
  return {};
}

/** Normalize a durable_id to the lowercase-hex form keys are stored/compared in. */
function norm(id: string | undefined | null): string {
  return (id || '').trim().toLowerCase();
}

/** A well-formed held entry — a stored blob that isn't is treated as absent (→ not fresh → fail-closed). */
function isHeldEntry(x: unknown): x is HeldAffirmative {
  if (!x || typeof x !== 'object') return false;
  const e = x as Record<string, unknown>;
  return typeof e.validUntil === 'number' && Number.isFinite(e.validUntil) && typeof e.epoch === 'number' && Number.isInteger(e.epoch);
}

/** Narrowing guard — a malformed/legacy map is treated as ABSENT by the caller (→ fail-closed). */
export function isHeldAffirmatives(x: unknown): x is HeldAffirmatives {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  return Object.values(x as Record<string, unknown>).every(isHeldEntry);
}

/**
 * Does the viewer hold a FRESH affirmative from this party? ★ FAIL-CLOSED: held === null (unreadable) ⇒ false
 * (don't surface). Never throws.
 */
export function holdsFreshAffirmative(held: HeldAffirmatives | null, durableId: string, now: number): boolean {
  if (held === null) return false; // unreadable ⇒ not fresh ⇒ don't surface (§F3 fail-closed)
  const e = held[norm(durableId)];
  return !!e && isAffirmFresh(e.validUntil, now);
}

/**
 * ★ THE REVEAL AND-GATE FILTER. Keeps only the fps from whom the viewer holds a FRESH affirmative — applied
 * to a disclosed_circle / they_trust list at the single canonical projection (contact-edge.ts). Combined with
 * the existing reveal predicate this is a monotonic AND-gate (can only HIDE more) ⇒ fail-closed-safe to layer.
 * ★ FAIL-CLOSED: held === null ⇒ [] (surface nothing); malformed/empty input ⇒ []. Never throws.
 */
export function affirmGateCircle(
  fps: readonly string[] | undefined,
  held: HeldAffirmatives | null,
  now: number,
): string[] {
  if (!Array.isArray(fps) || fps.length === 0) return [];
  if (held === null) return []; // unreadable ⇒ surface nothing (§F3 fail-closed)
  const seen = new Set<string>();
  const out: string[] = [];
  for (const fp of fps) {
    const id = norm(fp);
    if (!id || seen.has(id)) continue;
    if (holdsFreshAffirmative(held, id, now)) { seen.add(id); out.push(fp); }
  }
  return out;
}

/**
 * Record a received+verified affirmative (receive-path — next layer). MONOTONIC: only overwrite if the new
 * epoch is strictly higher (anti-rollback — a replayed older affirmative never shortens/extends the held one;
 * the receive-path also enforces this at verify, this is defense-in-depth). Returns a NEW map.
 */
export function recordAffirmative(
  held: HeldAffirmatives,
  durableId: string,
  affirm: HeldAffirmative,
): HeldAffirmatives {
  const id = norm(durableId);
  if (!id || !isHeldEntry(affirm)) return held;
  const prior = held[id];
  if (prior && prior.epoch >= affirm.epoch) return held; // monotonic — keep the higher epoch
  return { ...held, [id]: { validUntil: affirm.validUntil, epoch: affirm.epoch } };
}

/**
 * Drop expired entries (optional housekeeping — the gate already treats expired as not-fresh, so this is a
 * size-bound GC, not a correctness requirement). Returns a NEW map. Pure given `now`.
 */
export function pruneExpired(held: HeldAffirmatives, now: number): HeldAffirmatives {
  const out: HeldAffirmatives = {};
  for (const [id, e] of Object.entries(held)) {
    if (isHeldEntry(e) && isAffirmFresh(e.validUntil, now)) out[id] = e;
  }
  return out;
}
