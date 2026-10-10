// src/lib/trust/trust-affirm-consume.ts
// The ACCEPT half of the mutual-trust wire (increment 2) — mirror of messaging acceptInboundNote.
// AUTHENTICATE → BIND-TO-ME → ADMIT (in-book) → APPLY (flip they_trust_me / reciprocal). Kept
// store-free + crypto-light: both the admit check and the state-apply are INJECTED seams, so this is
// unit-testable with no IndexedDB and the live wiring (buildTrustAffirmSeam in live-book-poll) binds
// the client-store.
//
// WHY the admit gate is load-bearing (Flint #167514, FALSE-MUTUAL gate): a VALID signature proves only
// WHO signed — anyone can mint a canonical identity and send a verified "I trust you". Flipping
// they_trust_me off a verified-but-UNKNOWN sender would spam the recipient with "X trusts you · trust
// back?" (harassment + a step toward a false-mutual if they are induced to trust back). So the flip
// fires ONLY for a sender already IN THE BOOK — verified ≠ sufficient. A verified stranger affirmation
// is DROPPED terminally (ack-delete, no flip, no echo — same silent I-1/I-2 custody as a stranger note).
//
// WHY it can never unilaterally make an edge MUTUAL (defense-in-depth beyond the admit gate): the apply
// sink computes reciprocal = (I independently trust them) && trusts, reading the recipient's EXISTING
// trusted state — which a remote wire can never promote (updateContact's pt5 verify-before-trust gate).
// So an in-book affirm can set "they trust me" (inbound) but reciprocal/mutual requires MY own prior,
// owner-verified trust. No wire-driven promotion.

import { verifyTrustAffirmSender, type TrustAffirmWireV0 } from './trust-affirm';

/** The result of applying a verified+admitted affirmation to the recipient's store. */
export interface MutualApplyResult {
  /** The applied contact's local record id — for the live-repaint emit (reuses the contact beat). */
  id: string;
  /** reciprocal = (recipient independently trusts the sender) && trusts. Drives the "Mutual" phase. */
  reciprocal: boolean;
}

export interface AcceptTrustAffirmDeps {
  /** The decrypted, type-checked affirmation (from trustAffirmOpenpgpDecryptor). */
  wire: TrustAffirmWireV0;
  /** The recipient's own fingerprint — the affirmation's to_fingerprint MUST equal it (bind-to-me). */
  ownerFingerprint: string;
  /** True iff `fromFingerprint` is already in the recipient's book (whitelist-on-fetch admit, I-2). */
  isAdmitted: (fromFingerprint: string) => Promise<boolean>;
  /**
   * Persist the flip to the recipient's store and return {id, reciprocal}. Called ONLY after authn +
   * bind-to-me + admit all pass. MUST resolve before the caller acks (ack-follows-persist): a throw
   * propagates → the consume loop leaves the envelope for retry (at-least-once; the apply is idempotent
   * on (fromFingerprint, trusts)).
   */
  applyMutual: (fromFingerprint: string, trusts: boolean) => Promise<MutualApplyResult>;
}

/** What a persisted affirmation surfaces for the trust-repaint (null = dropped). */
export interface AcceptedTrustAffirm {
  id: string;
  from_fingerprint: string;
  trusts: boolean;
  reciprocal: boolean;
}

/**
 * Accept an inbound trust-affirmation. Returns the applied result for the repaint, or null if DROPPED
 * (unsigned / forged / misaddressed / stranger — silent I-1/I-2, terminal). THROWS only if applyMutual
 * throws (a store I/O failure) → the caller treats it as retryable.
 */
export async function acceptTrustAffirm(deps: AcceptTrustAffirmDeps): Promise<AcceptedTrustAffirm | null> {
  const { wire, ownerFingerprint, isAdmitted, applyMutual } = deps;

  // (1) AUTHENTICATE before anything else (Flint #55 gate): from_fingerprint is attacker-controlled
  //     until the signature verifies and binds to the carried public_key. Unsigned / forged ⇒ drop.
  if (!(await verifyTrustAffirmSender(wire))) return null;

  // (2) BIND-TO-ME: the signed to_fingerprint MUST be the recipient. The seal already guarantees only we
  //     can decrypt, but the signature binds `to` — so a captured affirmation addressed to someone else
  //     (were it ever re-sealed to us) can't drive our state. Fail-closed, defense-in-depth.
  if (wire.to_fingerprint !== ownerFingerprint) return null;

  // (3) ADMIT (whitelist-on-fetch, I-2 — the FALSE-MUTUAL gate): flip ONLY for an in-book sender.
  //     A verified stranger is dropped terminally — no flip, no "trusts you" echo.
  if (!(await isAdmitted(wire.from_fingerprint))) return null;

  // (4) APPLY — persist the flip (they_trust_me = trusts; reciprocal = own-trust && trusts). A throw
  //     propagates to the caller as retryable (ack-follows-persist). Idempotent on redelivery.
  const applied = await applyMutual(wire.from_fingerprint, wire.trusts);
  return {
    id: applied.id,
    from_fingerprint: wire.from_fingerprint,
    trusts: wire.trusts,
    reciprocal: applied.reciprocal,
  };
}
