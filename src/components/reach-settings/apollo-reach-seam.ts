/**
 * CUR-10 · Apollo disclosure-reach seam (STUB — UI half of KB#87355).
 *
 * ⛔ NEVER implement `visible()` / `reach()` / edge-filtering here.
 * Apollo owns gate-logic. Glass records owner intent via `reach-prefs.ts`
 * and will CALL fleet hooks once they land — never invent the gate.
 *
 * Expected fleet surface (ask Apollo to confirm / rename in the PR):
 *   - `setOwnerReachPolicy(policy)` — persist + publish consent-by-inclusion
 *     payload that makes opted-out bonds UN-COMPUTABLE (not client-hidden).
 *   - `getOwnerReachPolicy()` — restore intent for this chrome.
 *   - Viewer path stays `visible(graph, viewer)` — fail-closed + timing-uniform.
 *
 * Until those land, `commitReachIntent` only writes local prefs and returns
 * `stub-not-live`. Do not pretend disclosure is enforced.
 */

import {
  type ReachLevel,
  type ReachPrefs,
  writeReachPrefs,
} from './reach-prefs';

export type ReachPolicyCommitResult =
  | { status: 'stub-not-live'; prefs: ReachPrefs }
  | { status: 'live'; prefs: ReachPrefs };

export type OwnerReachPolicy = {
  awakenCircle: boolean;
  defaultReach: ReachLevel;
  /** Per-peer narrow-only overrides (fingerprint → reach). */
  edgeReach: Record<string, ReachLevel>;
};

/** Map glass prefs → the shape fleet is expected to accept. */
export function prefsToOwnerReachPolicy(prefs: ReachPrefs): OwnerReachPolicy {
  return {
    awakenCircle: prefs.awakenCircle,
    defaultReach: prefs.defaultReach,
    edgeReach: { ...prefs.edgeReach },
  };
}

/**
 * Persist local intent. When Apollo wires `setOwnerReachPolicy`, call it here
 * and return `{ status: 'live' }`. Until then: local only + stub-not-live.
 */
export async function commitReachIntent(
  prefs: ReachPrefs
): Promise<ReachPolicyCommitResult> {
  writeReachPrefs(prefs);
  // Fleet hook placeholder — do not invent publish / gate call.
  // await setOwnerReachPolicy(prefsToOwnerReachPolicy(prefs));
  return { status: 'stub-not-live', prefs };
}
