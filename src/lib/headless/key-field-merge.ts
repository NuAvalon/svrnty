// src/lib/headless/key-field-merge.ts — group-atomic key-field merge
// (admit-card-key-hash-bind-001 leg-b, dependency-free).
//
// upsertContact's shallow {...old, ...new} let a card missing some key
// fields PERSIST the old row's legs — a cross-epoch quad that derived to
// a Frankenstein fp (ember's 19:27 mixed-quad stale-card). Key material
// now moves as one epoch: a card carrying ANY key field takes ALL of
// them from it (absent legs cleared, never overlaid); a card carrying
// none is a metadata update and leaves key material untouched.
//
// Kept dependency-free deliberately — headless-store.ts is node:fs-only
// by contract; the crypto-bound side (canonical derivation) lives in
// admit-bind.ts which only async ingestion paths import.

/** Key-material fields that must move as one epoch — never overlayed. */
export const CARD_KEY_FIELDS = [
  'public_key',
  'pq_sig_public_key',
  'pq_kem_public_key',
] as const;

export function mergeKeyFieldsGroup<T extends Record<string, unknown>>(
  old: T,
  nu: T,
): T {
  const merged: T = { ...old, ...nu };
  if (CARD_KEY_FIELDS.some((k) => nu[k] !== undefined)) {
    for (const k of CARD_KEY_FIELDS) {
      merged[k] = nu[k] as T[Extract<keyof T, string>];
    }
  }
  return merged;
}
