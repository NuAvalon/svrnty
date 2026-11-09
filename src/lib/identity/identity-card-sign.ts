// src/lib/identity/identity-card-sign.ts
// (A) signed identity card — the pq_kem_public_key carry + its authentication. Mirrors
// trust/slug-claim.ts field-for-field (the Tier-0 signed-object exemplar); do NOT hand-roll crypto.
//
// WHY SIGNED. An identity-exchange card carries the peer's post-quantum keys (pq_kem for hybrid
// encryption; pq_sig for future ML-DSA verify). On a NON-enveloped carrier (ContactManagement
// QR/NFC/copy-paste) a channel-MITM could swap pq_kem undetected, because the fingerprint binds
// ONLY the classical public_key (fingerprint.ts hashes public_key; no kem in the fingerprint path).
// A future quantum adversary who harvested the ciphertext + broke classical DH would then hold both
// legs — the exact HNDL attack ML-KEM exists to stop. So the card is SIGNED and every carrier
// re-verifies on import:
//   (a) the envelope signature verifies against card.identity.public_key, AND
//   (b) card.identity.fingerprint === H(card.identity.public_key)  (fingerprintMatchesKey, Invariant-1).
// Together they bind pq_kem to the fingerprint via the classical key — the signature COMPLETES
// Invariant-1 to cover the pq key it doesn't today.
//
// The byte-exact envelope lives in crypto/sign-envelope.ts; the canonical bytes in format/canonical.ts;
// the domain tag + signing-input in format/envelope.ts (single-source, so sign≡verify can't drift).

import type { IdentityCard } from '../format/envelope';
import { DOMAIN_IDENTITY_CARD, identityCardSigningInput } from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, envelopeSignatureOf } from '../crypto/sign-envelope';
import { fingerprintMatchesKey } from './fingerprint';
// piece-2 device-mailbox: validate the seal-target the card carries. extractValidMailboxFromCard is the
// shape/content-fp gate ON TOP of the card signature (the mailbox fields live under identity.* so the
// signature already covers them); validateMailboxPublic re-checks the owner's own cached block on send.
import { extractValidMailboxFromCard, validateMailboxPublic, type DeviceMailboxPublic } from './device-mailbox';
// #588 T4 (dark): the beacon key's receiver checks. beacon-key.ts loads its curve library lazily, ONLY when a card actually carries the field.
import { checkBeaconPublicKey, type BeaconKeyReason } from '../crypto/beacon-key';

import { generationProblem, type GenerationProblem } from '../crypto/beacon-generation';
// ── §6 Suite-length validation: the ek length IS the suite discriminant ──────────
// ML-KEM ek (public-key) sizes are bijective with the parameter set, so a valid card needs no
// separate suite_id field — the length names the suite under the signature. This is the SINGLE
// SOURCE of suite-truth. Two load-bearing conditions:
//   1. DOWNGRADE-FLOOR: the map holds ONLY svrnty-sanctioned suites. ML-KEM-512 (800 B) is BELOW
//      the security floor and is deliberately absent → a 512 key derives `undefined` → 4c (dropped).
//   2. ENCAP MUST DERIVE IDENTICALLY: when `hybridEncapsulate` gets its first caller it MUST pick
//      ML-KEM params from the STORED key's length via THIS SAME map — never hardcode 1024. Import-
//      validate and encrypt-time must agree, or length-as-suite is unsound. (Zero callers today.)
export const EK_LEN_TO_SUITE: Record<number, string> = {
  1184: 'ML-KEM-768',   // Cat-3
  1568: 'ML-KEM-1024',  // Cat-5
};

/**
 * Decoded byte length of a base64 string, computed arithmetically (no atob/Buffer — identical in
 * browser and the tsc→node test env). Throws on non-base64 / bad padding so a malformed key routes
 * to 4c (undefined suite), never to a false accept.
 */
function base64ByteLength(b64: string): number {
  const s = b64.trim();
  if (s.length === 0 || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    throw new Error('not valid base64');
  }
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  return (s.length * 3) / 4 - pad;
}

/** The svrnty suite implied by a base64 ML-KEM public key's decoded length, or undefined if
 *  unsupported/below-floor/malformed. undefined ⇒ import branch 4c (soft-info, pq dropped). */
export function suiteFromKemLength(pqKemPublicKeyB64: string): string | undefined {
  if (!pqKemPublicKeyB64) return undefined;
  try {
    return EK_LEN_TO_SUITE[base64ByteLength(pqKemPublicKeyB64)];
  } catch {
    return undefined;
  }
}

/** A signed identity card: the card fields plus the envelope signature over them (TOP-LEVEL). */
export interface SignedIdentityCard extends IdentityCard {
  signature: string;      // classical (ED25519 / PGP armored)
  pq_signature?: string;  // ML-DSA-87 (hybrid — follow-up §7, not launch)
}

/**
 * Sign an identity card (client-side). Binds the WHOLE card — incl. pq_sig_public_key AND
 * pq_kem_public_key — under the identity-card domain, proving private-key possession over exactly
 * this card. LAUNCH = classical-only (omit pqSigningSecretKey → SUITE_CLASSICAL); the anti-downgrade
 * envelope makes adding ML-DSA later clean and un-strippable.
 */
export async function signIdentityCard(
  card: IdentityCard,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedIdentityCard> {
  const sig = await signWithEnvelope(
    DOMAIN_IDENTITY_CARD,
    identityCardSigningInput(card),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
  );
  const signed: SignedIdentityCard = { ...card, signature: sig.classical };
  if (sig.pq_signature) signed.pq_signature = sig.pq_signature;
  return signed;
}

/**
 * Verify a signed identity card — mirrors verifySignedSlugClaim (returns false, NEVER throws).
 * BOTH must hold:
 *   1. card.identity.fingerprint === H(card.identity.public_key)  (Invariant-1), and
 *   2. the envelope signature verifies against card.identity.public_key over the canonical card.
 * A false result means the caller (JoinerCeremony) MUST NOT store the pq keys — degrade to
 * classical-only per the fail-closed table (§4). This returns a single boolean; the caller
 * distinguishes "no signature present" (branch 2, quiet) from "signature invalid" (branch 3, loud)
 * by checking for the `signature` field before calling.
 */
export async function verifySignedIdentityCard(
  card: SignedIdentityCard,
  pqSigningPublicKey?: Uint8Array,
): Promise<boolean> {
  // Defensive fail-closed: a card parsed from an untrusted carrier may be malformed.
  const id = card?.identity;
  if (!id || typeof id.public_key !== 'string' || typeof id.fingerprint !== 'string') return false;
  if (typeof card.signature !== 'string' || card.signature.length === 0) return false;

  // (1) fingerprint↔key binding — cheap, checked first. Pass PQ pubs when present so a
  // four-key identity id matches; placeholder/short PQ falls through to the OpenPGP 40-hex check.
  if (!(await fingerprintMatchesKey(id.fingerprint, id.public_key, {
    kem_public_key: id.pq_kem_public_key,
    sig_public_key: id.pq_sig_public_key,
  }))) return false;

  // (2) envelope signature over the canonical card. Strip BOTH signature fields before recomputing
  // the signing input — the signer signed the card without them (identityCardSigningInput excludes them).
  const { signature, pq_signature, ...cardFields } = card;
  const envSig = envelopeSignatureOf(signature, pq_signature); // raw: '' / null refuse (#717)
  return verifyWithEnvelope(
    DOMAIN_IDENTITY_CARD,
    identityCardSigningInput(cardFields),
    envSig,
    id.public_key,
    pqSigningPublicKey,
  );
}

// ── SEND side: assemble + sign a card from a stored identity (both send-paths share this) ────
// Ceremony (relay) and ContactManagement (QR/copy) both call this so the signed shape can NEVER
// drift between carriers. pq_* come from the identity's post_quantum block (its PUBLIC keys); a
// v1/no-PQ identity yields '' → the card is signed over the ABSENCE, which the receiver reads as
// branch-4a (quiet, no pq). Signing needs the classical private key ⇒ the session must be unlocked;
// the caller loads it via loadKey() and handles the locked case.
export async function buildSignedIdentityCard(
  identity: any,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  entityType?: 'agent' | 'human' | 'org',
  beacon?: { publicKey: string; keyGeneration: number },
): Promise<SignedIdentityCard> {
  const idData = identity?.identity ?? identity;
  if (!idData?.fingerprint || !idData?.public_key) {
    throw new Error('cannot sign identity card — identity is missing fingerprint or public_key');
  }
  // post_quantum lives at the identity WRAPPER top-level (genesis: browser-identity.ts:163), a
  // SIBLING of the nested `.identity` — not on the unwrapped idData. Read both shapes: the flat
  // identity (post_quantum beside fingerprint) AND the genesis wrapper (post_quantum one level up).
  // Reading only idData.post_quantum dropped the legs for the wrapper shape → empty-pq cards (beat-3).
  const pq = idData?.post_quantum ?? identity?.post_quantum;
  // Same wrapper-aware read as post_quantum: genesis stores next_authority_commitment on the
  // wrapper (sibling of post_quantum), not on the nested `.identity` object.
  const next_authority_commitment =
    idData?.next_authority_commitment ?? identity?.next_authority_commitment ?? '';
  const card: IdentityCard = {
    version: '1.1',
    type: 'identity-exchange',
    created_at: new Date().toISOString(),
    identity: {
      fingerprint: idData.fingerprint,
      display_name: idData.display_name || idData.name || idData.slug || '',
      public_key: idData.public_key,
      email: idData.email || '',
      pq_sig_public_key: pq?.sig_public_key || '',
      pq_kem_public_key: pq?.kem_public_key || '',
      next_authority_commitment,
    },
  };
  // Bind the self-attested entity_type into the signed card (immutable, G-attest). Optional + byte-preserving:
  // omit it → the card canonicalizes exactly as a legacy card. Read from an explicit arg OR the identity input.
  const et = entityType ?? idData?.entity_type ?? identity?.entity_type;
  if (et !== undefined) {
    if (et !== 'agent' && et !== 'human' && et !== 'org')
      throw new Error(`buildSignedIdentityCard: entity_type must be one of {agent, human, org}, got ${String(et)}`);
    card.entity_type = et;
  }
  // piece-2: carry the PUBLIC device-mailbox (onion seal-target) if the identity has one. Read from the
  // wrapper like post_quantum/next_authority_commitment; validate (content-fp self-consistency) and OMIT
  // when absent/invalid so a legacy/pre-feature card canonicalizes identically (byte-preserving; never
  // null). Signed because it sits under identity.* — a receiver re-verifies it the same as pq_kem.
  const dmb = validateMailboxPublic(idData?.device_mailbox ?? identity?.device_mailbox);
  if (dmb) {
    card.identity.mailbox_fp = dmb.mailbox_fp;
    card.identity.mailbox_x25519_pk = dmb.mailbox_x25519_pk;
    card.identity.mailbox_mlkem1024_pk = dmb.mailbox_mlkem1024_pk;
  }
  // #588 T4 (dark): carry the beacon PUBLIC key + its generation under identity.* (signed). OMITTED when no beacon is given, so every
  // existing card canonicalizes byte-for-byte as before. The SENDER refuses to sign a key the receiver rule would drop.
  if (beacon !== undefined) {
    const gp = generationProblem(beacon.keyGeneration, Math.floor(Date.now() / 1000));
    if (gp) throw new Error(`buildSignedIdentityCard: beacon key_generation refused (${gp})`);
    const chk = await checkBeaconPublicKey(beacon.publicKey);
    if (!chk.ok) throw new Error(`buildSignedIdentityCard: beacon key refused (${chk.reason})`);
    card.identity.beacon_public_key = beacon.publicKey;
    card.identity.beacon_key_generation = beacon.keyGeneration;
  }
  // Build-time self-consistency guard (N2 class-killer — Archie ⚡9693 + Hypatia's claim-honesty vote):
  // a card whose canonical fingerprint claims 4 keys MUST carry all 4. Assert the card binds to its
  // OWN carried keys BEFORE it can be constructed, so a self-inconsistent card (fp≠carried-keys — e.g.
  // the empty-pq-legs beat-3 bug) is uninstantiable at the send-side, not caught downstream at a peer.
  if (!(await fingerprintMatchesKey(
    card.identity.fingerprint,
    card.identity.public_key,
    { kem_public_key: card.identity.pq_kem_public_key, sig_public_key: card.identity.pq_sig_public_key },
  ))) {
    throw new Error(
      'refusing to build a self-inconsistent identity card — fingerprint does not bind to its carried keys (missing/mismatched PQ legs?)',
    );
  }
  return signIdentityCard(card, classicalPrivateKeyArmored, classicalPassphrase);
}

// ── RECEIVE side: the fail-closed 4-branch import disposition (both receive-paths share this) ──
// JoinerCeremony (relay/QR) and ContactManagement.handleImportExchange (copy/paste) BOTH call this
// so the security decision can't drift between carriers (every carrier ends at
// verifySignedIdentityCard). Pure decision — it stores nothing; the caller applies `pq` + `alarm`.
export interface ImportDisposition {
  /** Import the classical contact at all? false ONLY for branch 1 (fp-fail / malformed card). */
  importClassical: boolean;
  /** Authenticated pq fields to STORE on the record, or null (drop pq). Non-null ONLY for 4b. */
  pq: { pq_kem_public_key: string; pq_sig_public_key: string } | null;
  /** UI disposition: reject (no import) · quiet (benign) · loud (possible tampering) · soft-info (unsupported suite). */
  alarm: 'reject' | 'quiet' | 'loud' | 'soft-info';
  /** Which branch fired — for tests, the UI message, and telemetry. */
  branch: 1 | 2 | 3 | '4a' | '4b' | '4c';
  /** Derived svrnty suite (4b only). */
  suite?: string;
  /**
   * piece-2: the VALIDATED public device-mailbox (onion seal-target) to STORE on the contact, or null to
   * drop it. Non-null ONLY under a VALID signature (any of 4a/4b/4c) AND a present + content-fp-consistent
   * mailbox block — a seal-target is as MITM-sensitive as pq_kem, so branches 1/2/3 (reject / no-sig /
   * invalid-sig) always drop it (emit to that peer under-reveals, fail-closed). Orthogonal to the pq
   * sub-disposition: a valid signer may carry a mailbox but no pq (and vice-versa).
   */
  deviceMailbox: DeviceMailboxPublic | null;
  /**
   * #588 T4 (dark): the VALIDATED beacon key + generation to STORE on the contact, or null. Non-null ONLY under a VALID signature (branch 4) and a key
   * that passes checkBeaconPublicKey and the generation / anti-rollback rules. Dropped by construction in branches 1/2/3. A drop never rejects the card.
   */
  beaconKey: { publicKey: string; keyGeneration: number } | null;
  /** Why a PRESENT beacon key was dropped under a valid signature (a fixed word, never the input). Undefined when there was no beacon or it was kept. */
  beaconKeyDropped?: BeaconKeyReason | GenerationProblem | 'rollback' | 'conflict';
}

export interface ClassifyOptions {
  /** My own beacon public key: a contact's card carrying it is dropped (own-key). */
  ownBeaconPublicKey?: string;
  /** The highest beacon key already stored for this identity: a lower generation is a rollback; the same generation with another key is a conflict. */
  knownBeacon?: { publicKey: string; keyGeneration: number };
  /** The RECEIVER's clock in whole seconds (default: now). A generation beyond now + 1 day is 'future', below the build floor is 'past'. */
  nowSeconds?: number;
}

/**
 * Classify a parsed identity-exchange card into its fail-closed import disposition.
 *   1  fp↔key FAILS / malformed        → REJECT the whole card (classical identity unverifiable).
 *   2  fp↔key OK, no `signature`        → classical-only, DROP pq, QUIET (benign pre-PQ peer).
 *   3  signature PRESENT but INVALID    → classical-only, DROP pq, LOUD (possible tampering).
 *   4  signature VALID → pq sub-disposition:
 *      4a pq_kem absent/empty           → QUIET, no pq (legit v1 signer; sig covers the absence).
 *      4b length ∈ EK_LEN_TO_SUITE      → STORE the authenticated pq (derived suite).
 *      4c length ∉ EK_LEN_TO_SUITE      → SOFT-INFO, no pq (sender bug, NOT tamper — a valid sig
 *                                         means a swapped kem is unreachable; §6/4c).
 * The core `verifySignedIdentityCard` collapses 2 and 3 into `false`; we split them here on the
 * PRESENCE of a non-empty `signature` field (branch 2 never calls verify).
 */
export async function classifyImportedCard(card: any, opts: ClassifyOptions = {}): Promise<ImportDisposition> {
  const id = card?.identity;
  // Malformed classical identity → branch 1 (nothing to import, nothing to trust).
  if (
    !id ||
    typeof id.public_key !== 'string' || id.public_key.length === 0 ||
    typeof id.fingerprint !== 'string' || id.fingerprint.length === 0
  ) {
    return { importClassical: false, pq: null, alarm: 'reject', branch: 1, deviceMailbox: null, beaconKey: null };
  }
  // BRANCH 1: fp↔classical-key binding (Invariant-1). Checked independently of verify — branch 2
  // never calls verify, and this decides classical-import for every branch.
  if (!(await fingerprintMatchesKey(id.fingerprint, id.public_key, {
    kem_public_key: id.pq_kem_public_key,
    sig_public_key: id.pq_sig_public_key,
  }))) {
    return { importClassical: false, pq: null, alarm: 'reject', branch: 1, deviceMailbox: null, beaconKey: null };
  }
  // fp↔key OK → the classical contact imports for branches 2/3/4.
  const hasSig = typeof card.signature === 'string' && card.signature.length > 0;
  // BRANCH 2: no signature → classical-only, quiet. Must NOT alarm (benign transition-era peer).
  if (!hasSig) {
    return { importClassical: true, pq: null, alarm: 'quiet', branch: 2, deviceMailbox: null, beaconKey: null };
  }
  // Signature present → verify (re-checks fp↔key internally; keeps verify self-contained).
  // The canonicalizer THROWS on a float / null / NaN anywhere in a signed structure, and a hostile card can carry one. We cannot canonicalize it, so we
  // cannot verify it: REJECT the whole card (branch 1, nothing stored) rather than store a classical-only contact for a card we could not read (Flint, 11-09).
  let valid: boolean;
  try {
    valid = await verifySignedIdentityCard(card as SignedIdentityCard);
  } catch {
    return { importClassical: false, pq: null, alarm: 'reject', branch: 1, deviceMailbox: null, beaconKey: null };
  }
  // BRANCH 3: present but invalid → classical-only, LOUD. Reserve the tamper alarm for THIS only.
  if (!valid) {
    return { importClassical: true, pq: null, alarm: 'loud', branch: 3, deviceMailbox: null, beaconKey: null };
  }
  // BRANCH 4: valid signature. The seal-target (device-mailbox) is now authenticated under identity.* —
  // extract + content-fp-validate it ONCE here (orthogonal to the pq suite decision below). Absent/invalid
  // → null (emit under-reveals). Dropped by construction in branches 1/2/3 above (no valid signature).
  const deviceMailbox = extractValidMailboxFromCard(id);
  const beacon = await classifyBeaconKey(id, opts);
  // pq sub-disposition:
  const kem = typeof id.pq_kem_public_key === 'string' ? id.pq_kem_public_key : '';
  // 4a: absent/empty pq_kem under a valid sig → legit v1/no-PQ signer. Quiet, no pq.
  if (kem === '') {
    return { importClassical: true, pq: null, alarm: 'quiet', branch: '4a', deviceMailbox, ...beacon };
  }
  const suite = suiteFromKemLength(kem);
  // 4c: valid sig, unsupported/malformed suite length → sender bug, NOT tampering. Soft-info, no pq.
  if (!suite) {
    return { importClassical: true, pq: null, alarm: 'soft-info', branch: '4c', deviceMailbox, ...beacon };
  }
  // 4b: valid sig + supported suite → STORE the authenticated pq (both keys, as carried).
  const sig = typeof id.pq_sig_public_key === 'string' ? id.pq_sig_public_key : '';
  return {
    importClassical: true,
    pq: { pq_kem_public_key: kem, pq_sig_public_key: sig },
    alarm: 'quiet',
    branch: '4b',
    suite,
    deviceMailbox,
    ...beacon,
  };
}

/** #588 T4 (dark): decide what to do with the beacon fields of a card whose signature already VERIFIED. Never throws; a drop keeps the card. */
async function classifyBeaconKey(
  id: any,
  opts: ClassifyOptions,
): Promise<{ beaconKey: ImportDisposition['beaconKey']; beaconKeyDropped?: ImportDisposition['beaconKeyDropped'] }> {
  const hasKey = id?.beacon_public_key !== undefined, hasGen = id?.beacon_key_generation !== undefined;
  if (!hasKey && !hasGen) return { beaconKey: null }; // a card from before the field: nothing to say
  if (!hasKey) return { beaconKey: null, beaconKeyDropped: 'generation' };
  const gp = generationProblem(id.beacon_key_generation, opts.nowSeconds ?? Math.floor(Date.now() / 1000));
  if (gp) return { beaconKey: null, beaconKeyDropped: gp };
  const chk = await checkBeaconPublicKey(id.beacon_public_key, opts.ownBeaconPublicKey);
  if (!chk.ok) return { beaconKey: null, beaconKeyDropped: chk.reason };
  const k = opts.knownBeacon;
  if (k) {
    if (id.beacon_key_generation < k.keyGeneration) return { beaconKey: null, beaconKeyDropped: 'rollback' };
    if (id.beacon_key_generation === k.keyGeneration && id.beacon_public_key !== k.publicKey) return { beaconKey: null, beaconKeyDropped: 'conflict' };
  }
  return { beaconKey: { publicKey: id.beacon_public_key as string, keyGeneration: id.beacon_key_generation as number } };
}
