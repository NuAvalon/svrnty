/**
 * CUR-10 · reach-settings preferences — UI chrome ONLY (localStorage).
 *
 * ⛔ Apollo owns `visible()` / `reach()` gate-logic (KB#87355 UI-half contract).
 * This module stores the owner's disclosure INTENT. It never decides which
 * edges a peer may see, never filters the Trust Map, and never fetch-then-hides.
 *
 * Composition (authoring rule — gate enforces; glass only records):
 *   - "Awaken the circle" = global opt-in. Off → no bond disclosure.
 *   - Default reach = private | L1 | L2 for bonds without a per-edge override.
 *   - Per-edge reach may only NARROW relative to default (never widen).
 *   - Global-on never overrides a finer per-edge restriction.
 */

export const REACH_PREFS_KEY = 'svrnty.reach-settings';

/** How far a consented bond may be disclosed when the circle is awake. */
export type ReachLevel = 'private' | 'l1' | 'l2';

export type ReachPrefs = {
  /** Global opt-in — composes WITH per-edge reach; never widens a finer edge. */
  awakenCircle: boolean;
  /** Default bond disclosure when awaken is on and the edge has no override. */
  defaultReach: ReachLevel;
  /**
   * Per-peer overrides keyed by peer fingerprint (hex lower).
   * Missing key = inherit defaultReach.
   * Glass refuses to store a wider override than default (narrow-only).
   */
  edgeReach: Record<string, ReachLevel>;
};

export const DEFAULT_REACH_PREFS: ReachPrefs = {
  awakenCircle: false,
  defaultReach: 'private',
  edgeReach: {},
};

export const REACH_LEVEL_OPTIONS: ReadonlyArray<{
  value: ReachLevel;
  label: string;
  short: string;
  hint: string;
}> = [
  {
    value: 'private',
    label: 'Private',
    short: 'Only you',
    hint: 'This bond stays on your device — not disclosed to anyone else.',
  },
  {
    value: 'l1',
    label: 'Trusted (L1)',
    short: 'Trusted',
    hint: 'People you trust may see that this bond exists — never an inferred line.',
  },
  {
    value: 'l2',
    label: 'Circle (L2)',
    short: 'Circle',
    hint: 'Your trusted circle and theirs may see this bond — still consented, never inferred.',
  },
];

const VALID_REACH = new Set<ReachLevel>(['private', 'l1', 'l2']);

/** Ordinal for narrow-only checks — higher = wider disclosure. */
export function reachOrdinal(level: ReachLevel): number {
  if (level === 'private') return 0;
  if (level === 'l1') return 1;
  return 2;
}

/** Narrower of two levels (constitution: ACL may only restrict, never widen). */
export function narrowerReach(a: ReachLevel, b: ReachLevel): ReachLevel {
  return reachOrdinal(a) <= reachOrdinal(b) ? a : b;
}

export function normalizeFingerprintKey(fp: string): string {
  return fp.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}

export function parseReachPrefs(raw: string | null): ReachPrefs {
  if (!raw) return { ...DEFAULT_REACH_PREFS, edgeReach: {} };
  try {
    const parsed = JSON.parse(raw) as Partial<ReachPrefs>;
    const awakenCircle =
      typeof parsed.awakenCircle === 'boolean'
        ? parsed.awakenCircle
        : DEFAULT_REACH_PREFS.awakenCircle;
    const defaultReach =
      typeof parsed.defaultReach === 'string' && VALID_REACH.has(parsed.defaultReach as ReachLevel)
        ? (parsed.defaultReach as ReachLevel)
        : DEFAULT_REACH_PREFS.defaultReach;

    const edgeReach: Record<string, ReachLevel> = {};
    if (parsed.edgeReach && typeof parsed.edgeReach === 'object') {
      for (const [k, v] of Object.entries(parsed.edgeReach)) {
        if (typeof v !== 'string' || !VALID_REACH.has(v as ReachLevel)) continue;
        const key = normalizeFingerprintKey(k);
        if (!key) continue;
        // Refuse stored widen vs default (narrow-only).
        edgeReach[key] = narrowerReach(v as ReachLevel, defaultReach);
      }
    }

    return { awakenCircle, defaultReach, edgeReach };
  } catch {
    return { ...DEFAULT_REACH_PREFS, edgeReach: {} };
  }
}

export function readReachPrefs(): ReachPrefs {
  if (typeof localStorage === 'undefined') {
    return { ...DEFAULT_REACH_PREFS, edgeReach: {} };
  }
  try {
    return parseReachPrefs(localStorage.getItem(REACH_PREFS_KEY));
  } catch {
    return { ...DEFAULT_REACH_PREFS, edgeReach: {} };
  }
}

export function writeReachPrefs(prefs: ReachPrefs): void {
  if (typeof localStorage === 'undefined') return;
  try {
    // Re-narrow edges against current default before persist.
    const edgeReach: Record<string, ReachLevel> = {};
    for (const [k, v] of Object.entries(prefs.edgeReach ?? {})) {
      const key = normalizeFingerprintKey(k);
      if (!key || !VALID_REACH.has(v)) continue;
      edgeReach[key] = narrowerReach(v, prefs.defaultReach);
    }
    const clean: ReachPrefs = {
      awakenCircle: !!prefs.awakenCircle,
      defaultReach: VALID_REACH.has(prefs.defaultReach)
        ? prefs.defaultReach
        : DEFAULT_REACH_PREFS.defaultReach,
      edgeReach,
    };
    localStorage.setItem(REACH_PREFS_KEY, JSON.stringify(clean));
  } catch {
    /* ignore quota / private mode */
  }
}

/**
 * Effective authoring reach for one bond — UI display helper ONLY.
 * Does NOT replace Apollo `visible()` / `reach()`. When awaken is off → private.
 * Per-edge override (if any) is already narrow-only vs default.
 */
export function effectiveBondReach(
  prefs: ReachPrefs,
  peerFingerprint: string
): ReachLevel {
  if (!prefs.awakenCircle) return 'private';
  const key = normalizeFingerprintKey(peerFingerprint);
  const override = key ? prefs.edgeReach[key] : undefined;
  if (override && VALID_REACH.has(override)) {
    return narrowerReach(override, prefs.defaultReach);
  }
  return prefs.defaultReach;
}

/** Set or clear a per-edge override (narrow-only vs default). */
export function withEdgeReach(
  prefs: ReachPrefs,
  peerFingerprint: string,
  level: ReachLevel | 'inherit'
): ReachPrefs {
  const key = normalizeFingerprintKey(peerFingerprint);
  if (!key) return prefs;
  const edgeReach = { ...prefs.edgeReach };
  if (level === 'inherit') {
    delete edgeReach[key];
  } else {
    edgeReach[key] = narrowerReach(level, prefs.defaultReach);
  }
  return { ...prefs, edgeReach };
}

/** Claim-honest status line for the settings panel. */
export function reachStatusLine(prefs: ReachPrefs): string {
  if (!prefs.awakenCircle) {
    return 'Circle is asleep — bonds stay private on this device. Awaken never infers a line.';
  }
  const opt = REACH_LEVEL_OPTIONS.find((o) => o.value === prefs.defaultReach);
  const edgeCount = Object.keys(prefs.edgeReach).length;
  const edgeBit =
    edgeCount === 0
      ? 'no per-bond overrides'
      : `${edgeCount} per-bond override${edgeCount === 1 ? '' : 's'} (narrower only)`;
  return `Circle awake · default ${opt?.label ?? prefs.defaultReach} · ${edgeBit}. Gate enforcement is fleet-owned — prefs here are your consent intent.`;
}

export function reachLevelLabel(level: ReachLevel): string {
  return REACH_LEVEL_OPTIONS.find((o) => o.value === level)?.label ?? level;
}
