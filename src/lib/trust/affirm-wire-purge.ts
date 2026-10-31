// src/lib/trust/affirm-wire-purge.ts
// #593 affirm-wire removal — the PURE scrub decision for the device-held mutual-trust taint.
//
// The removed affirm-wire (deposit→consume→applyMutual) persisted `mutual.{they_trust_me,reciprocal,
// last_affirm_at}` onto contact records — a device-held "they trust me" bit that is FALSE SECURITY
// (defeated by inspecting the device). This pure helper decides whether a contact's `mutual` carries that
// taint and returns the scrubbed benign value. It is deliberately store-agnostic (no IndexedDB) so the
// decision is exhaustively unit-testable; client-store's one-time on-unlock purge applies it over every
// contact record (all bearers). See purgeAffirmWireMutualTaintOnUnlock in client-store.ts.
//
// DO-NO-HARM SCOPE: this returns ONLY a scrubbed `mutual` — it has no reach over the owner's own sovereign
// trust (trusted / trust_level / trusted_since / trust_history) or anything else on the record. The benign
// interaction timestamp `last_sync` is PRESERVED; `last_affirm_at` is dropped. Mutual is re-grounded on the
// blind PSI intersection (#588), never a device-held received bit.

/** The benign post-purge shape of `mutual` — no device-held trust claim, last_sync preserved. */
export interface ScrubbedMutual {
  they_trust_me: null;
  reciprocal: false;
  last_sync: string | null;
}

export interface AffirmWirePurgeResult {
  /** True iff the input carried affirm-wire taint and must be rewritten. */
  changed: boolean;
  /** The scrubbed mutual to persist — present ONLY when changed (else there is nothing to write). */
  mutual?: ScrubbedMutual;
}

/**
 * Decide whether a contact's `mutual` carries the removed affirm-wire taint, and if so return the
 * scrubbed value. IDEMPOTENT: a record already at the benign default (they_trust_me null, reciprocal
 * not true, no last_affirm_at) returns `{changed:false}` → the purge writes nothing, so re-running on
 * every unlock is a no-op. A missing `mutual` is likewise a no-op.
 */
export function scrubAffirmWireMutual(mutual: unknown): AffirmWirePurgeResult {
  const m = mutual as
    | { they_trust_me?: unknown; reciprocal?: unknown; last_affirm_at?: unknown; last_sync?: unknown }
    | null
    | undefined;
  if (!m || typeof m !== 'object') return { changed: false };

  const hasTaint =
    (m.they_trust_me !== null && m.they_trust_me !== undefined) ||
    m.reciprocal === true ||
    (m.last_affirm_at !== null && m.last_affirm_at !== undefined);

  if (!hasTaint) return { changed: false };

  return {
    changed: true,
    mutual: {
      they_trust_me: null,
      reciprocal: false,
      last_sync: (m.last_sync as string | null) ?? null, // benign timestamp — PRESERVED
    },
  };
}
