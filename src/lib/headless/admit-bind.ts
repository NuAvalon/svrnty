// src/lib/headless/admit-bind.ts — card key-material binding + group-atomic
// merge for the headless admit path (admit-card-key-hash-bind-001, flint's
// reconciliation ask).
//
// Two holes closed here, one source:
//
// (a) FP-BIND — headless-store upsertContact merges by CLAIMED
//     id||fingerprint: a card asserting any member's fp overwrote their row
//     regardless of whether its keys hash to it (the Weft-swap class — a
//     forged card lands the row, then every env from the real member
//     fp-mismatches). Bind the claim BEFORE upsert: derive the card's
//     canonical fp with the SAME canonicalPubsFromArmoredPublicKey quad
//     the consume gate's fp-check verifies against — a call into the
//     fleet's existing derivation, never a reimplementation.
//
// (b) MERGE ATOMICITY — the upsert was a shallow {...old, ...new}, so a
//     card missing some key fields PERSISTED the old row's legs and
//     produced a cross-epoch quad that derived to a Frankenstein fp
//     (ember's 19:27 mixed-quad stale-card). Key fields now move as a
//     group: a card carrying ANY of them takes ALL of them from it
//     (absent legs cleared, never overlaid); a card carrying none is a
//     metadata update and leaves key material untouched.

import {
  canonicalPubsFromArmoredPublicKey,
  canonicalClaimMatches,
} from '@/lib/identity/fingerprint';

export { mergeKeyFieldsGroup, CARD_KEY_FIELDS } from './key-field-merge';

/** The card's derived canonical fp, or null when the quad is underivable
 *  (missing/short PQ legs, unreadable armored key) — mirrors fp-check's
 *  own canonical-only 'false', never a throw. */
export async function derivedCardFp(
  armoredPublicKey: string,
  pqKemPublicKeyB64: string | undefined,
  pqSigPublicKeyB64: string | undefined,
): Promise<string | null> {
  try {
    const pubs = await canonicalPubsFromArmoredPublicKey(
      armoredPublicKey,
      pqKemPublicKeyB64 ?? '',
      pqSigPublicKeyB64 ?? '',
    );
    return pubs.fingerprint;
  } catch {
    return null;
  }
}

/** True iff the card's claimed fp matches what its keys derive to —
 *  canonicalClaimMatches allows a >=16-hex prefix claim exactly as
 *  fp-check does. */
export function cardFpBound(claimedFp: string, derivedFp: string): boolean {
  return canonicalClaimMatches(claimedFp, derivedFp);
}

/** Group-atomic key-field merge lives in ./key-field-merge (kept
 *  dependency-free for headless-store); re-exported here so callers get
 *  the whole admit-bind surface from one module. */
