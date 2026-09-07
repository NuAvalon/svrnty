// src/lib/trust/contact-update.ts
// 0.4 contact.update CONSUME-VERIFY floor — the client-side gate every inbound contact-card delta
// must pass before it is allowed to touch the stored address book. This is the Queue-B 0.4 lane
// (protocol half). Invariant canon §S1.
//
// WHY THIS EXISTS. 0.4 is the "living address book": a contact whose card changes (new phone, new
// key epoch, new relay routing) signs a delta and it propagates to everyone who holds their card.
// That is a *write path into the user's device from the network* — exactly the surface that, done
// naively, becomes contact-poisoning / routing-hijack / a liveness oracle
// (§D4). So the consume path is a hard
// gate, not a best-effort check.
//
// THE FLOOR (the E2E-invariant): "every consume-path verifies; once-signed-
// never-unsigned; a consume-path that skips verify must fail LOUDLY." This module has exactly ONE
// way to obtain a VerifiedContactUpdate — {@link verifyIncomingContactUpdate} — and it either returns
// a fully-verified value or THROWS {@link ContactUpdateRejected}. There is no boolean an eager caller
// can ignore and no silent-skip branch. The caller APPLIES the delta to storage only with a value
// this function returned; the apply step (which needs the 0.14 three-state Contact type) lives
// elsewhere in contacts/ and is deliberately NOT in this file — verify (trust/) and apply (contacts/)
// are separated precisely so apply cannot run without verify.
//
// RATIFY-PROOF ON BOTH AXES:
//   1) Crypto model (A/B): we DELEGATE all signature checking to the 0.1 envelope primitive
//      (verifyWithEnvelope). We never re-implement verification, so a ratify that changes the crypto
//      model changes the primitive's internals, not this file. We inherit domain-separation (a
//      trust-signal or slug-claim signature cannot verify as a contact.update) and anti-downgrade
//      (stripping the PQ half of a hybrid signature flips the bound suite → verification fails) for
//      free.
//   2) Verify boundary (E2E/server): this is the CLIENT consume-verify and it is UNCONDITIONAL. The
//      relay carries the SignedContactUpdate opaquely; whether or not a relay ever does a redundant
//      payload check, the client still verifies here. So this floor holds under either ratify outcome.
//
// INDISTINGUISHABILITY NOTE (I-1/I-2). The reject `reason` codes below are LOCAL diagnostics for the
// receiver. They must never be echoed back to the sender or the relay: a sender who could learn "your
// update was rejected because you're not my contact" would defeat indistinguishability (I-1) and make
// blocking detectable (I-2). Rejection here is silent to everyone but the local device.

import {
  DOMAIN_CONTACT_UPDATE,
  contactUpdateSigningInput,
  rotationSigningInput,
  type ContactUpdateEnvelope,
  type RotationSuccessorAuth,
  type SuccessorAuth,
} from '../format/envelope';
import { verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import {
  authorityCommitmentFromReveal,
  fingerprintMatchesKey,
  verifyRotationAuthority,
} from '../identity/fingerprint';

/**
 * Fields an inbound contact.update is allowed to change — a strict allowlist (firewall). An update
 * naming ANY field outside this set is rejected WHOLE (never partially applied), so the update
 * channel cannot be used to smuggle a field the address-book model never intended to accept.
 *
 * NOW-VOCAB {display_name, phones, emails, note}. The canonical invariant is `ALLOWED_FIELDS ≡ {fields the
 * 0.14 ContactRecord homes + contactToEdge surfaces}`, enforced IDENTICALLY in verify (here) and apply —
 * a divergence is a bug the merge-guard test catches. The set started as the minimal spartan floor
 * {display_name, note, emails}; `phones` is the FIRST EARNED GROW (producer = the vCard import; the dedup
 * engine's strongest key is the normalized phone — importing a contact without their number is broken).
 *
 * GROW-LATER IS FREE: the field vocabulary lives inside the signed `payload` (opaque to the relay,
 * hashed inside the signature — envelope §6), so adding a field later breaks NO signature, touches NO
 * relay, needs NO re-ratify; older receivers fail-closed on the unknown field (this firewall). Grow one
 * field at a time once it earns (a) a verified producer, (b) a contactToEdge home, (c) a real claim.
 * `phones` is now grown; `urls` remains the next grow-NEXT candidate (the 0.12 vCard import produces it).
 *
 * OUT OF contact.update ENTIRELY — these are their own signed object types, NOT card fields:
 *   - `public_key`  → `key.rotate`: a key rotation, not a field-set. Riding the plain field path would
 *     swap the active key while keeping the genesis fingerprint (bypassing the fingerprint↔key binding)
 *     and skip epoch-lineage verification (`epoch-ahead-needs-lineage` below). Rotation gets its own
 *     lineage-gated path.
 *   - `routing`     → `routing.update`: relay hints resolve to relays only (I-4), its own format freeze.
 *
 * Deliberately absent — and this absence is load-bearing, not an oversight:
 *   - device geolocation / coordinates / `location` / `lat` / `lng` / `ip`  → I-4 (reachability-not-
 *     location): routing resolves to relays only; nothing exposes where a person physically is.
 *   - `last_seen` / `presence` / `online` / `liveness`                      → I-6 (render provenance):
 *     nothing renders presence; a contact cannot push a "last seen" attribute into your view. The
 *     living/dim ignition is driven by the receiver's LOCAL witnessed-receipt clock (apply's
 *     last_interaction refresh), never a pushed field — confirmed I-6-safe.
 *
 * The PROPERTY — allowlist-firewall, no presence / no geolocation, verify≡apply — is invariant
 * regardless of the exact names; the names are the reconciliation seam.
 */
export const CONTACT_UPDATE_ALLOWED_FIELDS: ReadonlySet<string> = new Set([
  'display_name', // → typed ContactRecord.name (contactToEdge: peer_name)
  'phones', // → ContactRecord phones passthrough (vCard TEL, E.164-normalized); first earned grow
  'emails', // → primary to ContactRecord.email; full list on the emails passthrough
  'note', // → ContactRecord.notes (contactToEdge reads c.notes || c.metadata?.notes)
  'handles', // → messaging-app handles map {signal,whatsapp,telegram,discord,matrix,instagram,facebook}; reach-only, self-asserted. Method-grow. VALUE-guard (≤16 curated keys / ≤128-char values / sanitize-as-claimed) enforced recipient-side on apply + at send-UI; this firewall gates the KEY.
  'urls', // → website(s), string[]; reach-only (method-grow).
]);

/**
 * The curated messaging-app handle keys allowed inside a `handles` map — SHARED single-source so verify,
 * apply, and the send-UI enforce the SAME set (no drift, same reason CONTACT_UPDATE_ALLOWED_FIELDS is one
 * Set). Reach-only, self-asserted. Grow-later: add a key HERE (all under the already-grown 'handles'
 * field → no protocol/allowlist re-grow). Method-grow.
 */
export const CONTACT_HANDLE_KEYS: ReadonlySet<string> = new Set([
  'signal', 'whatsapp', 'telegram', 'discord', 'matrix', 'instagram', 'facebook',
]);

/** Recipient-side VALUE bounds for the structured method fields — the verify firewall fail-CLOSES on an
 *  abusive SIGNED handles map / urls list BEFORE apply (a valid signature doesn't make an oversized or
 *  off-curated map safe). Apply + send-UI additionally enforce these (defense-in-depth). */
export const HANDLES_MAX_COUNT = 16;
export const HANDLE_VALUE_MAX_LEN = 128;
export const URLS_MAX_COUNT = 8;
export const URL_VALUE_MAX_LEN = 512; // URLs run longer than handle values

/** A contact.update as it arrives off the wire: the envelope plus its detached envelope signature. */
export interface SignedContactUpdate {
  envelope: ContactUpdateEnvelope;
  signature: EnvelopeSignature;
}

/**
 * The receiver's last-VERIFIED state for the contact this update claims to be from. This narrow
 * interface is the seam that keeps 0.4-verify decoupled from the 0.14 Contact type: the full
 * Contact will satisfy it, but this module never imports it.
 */
export interface KnownContactIdentity {
  /** Durable, genesis-derived fingerprint — immutable across key rotations. */
  fingerprint: string;
  /** The epoch whose key we currently hold and trust for this contact. */
  epoch: number;
  /** The highest card `version` we have already accepted — the monotonic replay floor. */
  version: number;
  /** Armored classical (OpenPGP/Ed25519) public key valid AT `epoch`. */
  classicalPublicKeyArmored: string;
  /** Optional ML-DSA public key half, present iff we require/accept the hybrid suite for this contact. */
  pqSigningPublicKey?: Uint8Array;
  /** Epoch+1 authority pin (64-hex). '' for pre-mint/legacy contacts — rotation then fail-closes. */
  next_authority_commitment?: string;
}

/** A contact.update that passed every check. The caller MAY now apply `delta` to storage. */
export interface VerifiedContactUpdate {
  fingerprint: string;
  epoch: number;
  version: number;
  changed_fields: string[];
  delta: Record<string, unknown>;
}

export type ContactUpdateRejectReason =
  | 'malformed' // structurally invalid envelope/signature off the wire
  | 'wrong-origin' // envelope.fingerprint does not match the contact we hold
  | 'stale-version' // version <= last-seen (replay / rollback) — checked BEFORE any crypto
  | 'epoch-regression' // envelope.epoch < the epoch we trust
  | 'epoch-ahead-needs-lineage' // envelope.epoch > ours — must run successor-lineage catch-up first
  | 'field-not-allowed' // a changed_field is outside the allowlist firewall (I-4 / I-6)
  | 'field-value-invalid' // a structured field's VALUE is malformed/abusive (handles: non-map / >16 / off-curated / oversized; urls: non-array / oversized) — fail-closed BEFORE apply
  | 'undeclared-delta-field' // delta carries a key not declared in changed_fields (smuggling)
  | 'declared-field-missing' // changed_fields names a field absent from delta (dishonest manifest)
  | 'pq-required' // caller required the hybrid suite but the signature is classical-only
  | 'bad-signature' // the envelope signature did not verify (tamper / attribution / domain / downgrade)
  | 'rotation-unknown-kind' // successor kind is not 'rotation' — fail-closed (open discriminant)
  | 'rotation-commitment-mismatch' // revealed K_auth does not hash to the pre-committed pin
  | 'rotation-bad-authority-sig' // sig_by_authority does not verify under the revealed K_auth
  | 'rotation-epoch-not-next' // successor.epoch !== known.epoch + 1
  | 'rotation-fingerprint-mismatch'; // new_fingerprint does not bind the new operational pubs

/**
 * Thrown for EVERY rejection. Its existence is the "fail loud" floor: the only alternative to a
 * fully-verified return value is this exception — never a silently-ignorable `false`.
 */
export class ContactUpdateRejected extends Error {
  constructor(
    public readonly reason: ContactUpdateRejectReason,
    detail?: string,
  ) {
    super(detail ? `contact.update rejected (${reason}): ${detail}` : `contact.update rejected (${reason})`);
    this.name = 'ContactUpdateRejected';
  }
}

function isSafeCount(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Structural validation of an off-the-wire SignedContactUpdate. The relay carried this OPAQUELY, so
 * before any field logic we confirm it even has the shape of a contact.update — an unsigned or
 * malformed blob is rejected here, which is itself one instance of "unsigned ⇒ fail loud".
 */
function assertWellFormed(signed: unknown): asserts signed is SignedContactUpdate {
  if (!isPlainObject(signed)) throw new ContactUpdateRejected('malformed', 'not an object');
  const { envelope, signature } = signed as Record<string, unknown>;

  if (!isPlainObject(envelope)) throw new ContactUpdateRejected('malformed', 'missing envelope');
  const e = envelope as Record<string, unknown>;
  if (typeof e.fingerprint !== 'string' || e.fingerprint.length === 0)
    throw new ContactUpdateRejected('malformed', 'fingerprint');
  if (!isSafeCount(e.epoch)) throw new ContactUpdateRejected('malformed', 'epoch');
  if (!isSafeCount(e.version)) throw new ContactUpdateRejected('malformed', 'version');
  if (typeof e.updated_at !== 'string') throw new ContactUpdateRejected('malformed', 'updated_at');
  if (!Array.isArray(e.changed_fields) || !e.changed_fields.every((f) => typeof f === 'string'))
    throw new ContactUpdateRejected('malformed', 'changed_fields');
  if (!isPlainObject(e.delta)) throw new ContactUpdateRejected('malformed', 'delta');

  // Signature must at least carry a classical part; the PQ half is optional (its presence selects the
  // suite inside the primitive). An absent/empty signature is the canonical "unsigned" rejection.
  if (!isPlainObject(signature)) throw new ContactUpdateRejected('malformed', 'missing signature');
  if (typeof (signature as Record<string, unknown>).classical !== 'string')
    throw new ContactUpdateRejected('malformed', 'signature.classical');
}

/**
 * Verify an inbound contact.update against what we already know about the contact, and return the
 * verified delta — or throw {@link ContactUpdateRejected}. THIS IS THE ONLY WAY to obtain a
 * {@link VerifiedContactUpdate}; there is no verify-skipping path.
 *
 * Checks run cheap-and-non-crypto FIRST (attribution, monotonic version, epoch, the field firewall)
 * and the expensive signature verify LAST. That ordering is deliberate:
 *   - the frozen envelope format mandates "reject version <= last-seen BEFORE any sig work"
 *     (src/lib/format/envelope.ts) — a rollback/replay is dropped without spending a verification, and
 *   - a malformed or off-allowlist blob cannot burn signature CPU (DoS resistance).
 * A stale or misattributed update is therefore rejected even if it carries a perfectly valid signature.
 *
 * @param signed the wire object (relay-opaque): { envelope, signature }
 * @param known  our last-verified identity/version state for this contact (the seam)
 * @param opts.requirePq  reject a classical-only signature (enforce the hybrid suite for this contact)
 */
export async function verifyIncomingContactUpdate(
  signed: SignedContactUpdate,
  known: KnownContactIdentity,
  opts: { requirePq?: boolean } = {},
): Promise<VerifiedContactUpdate> {
  assertWellFormed(signed);
  const { envelope, signature } = signed;

  // 1) Attribution: the update must claim to be from the exact contact we hold.
  if (envelope.fingerprint !== known.fingerprint)
    throw new ContactUpdateRejected('wrong-origin', `${envelope.fingerprint} != ${known.fingerprint}`);

  // 2) Monotonic version — the replay/rollback floor, BEFORE any crypto (frozen-format rule).
  //    updated_at is display/audit only and is intentionally NOT an ordering input (clocks lie).
  if (envelope.version <= known.version)
    throw new ContactUpdateRejected('stale-version', `v${envelope.version} <= seen v${known.version}`);

  // 3) Epoch: we can only check a signature against the key we hold, which is valid at `known.epoch`.
  if (envelope.epoch < known.epoch)
    throw new ContactUpdateRejected('epoch-regression', `epoch ${envelope.epoch} < ${known.epoch}`);
  if (envelope.epoch > known.epoch)
    // A newer epoch is signed by a successor key we do not yet hold. Do NOT accept it blind —
    // the caller must first run verifyRotationSuccessor to adopt the new epoch, then retry.
    throw new ContactUpdateRejected('epoch-ahead-needs-lineage', `epoch ${envelope.epoch} > ${known.epoch}`);

  // 4) Field firewall — the whole update is rejected if it names any field outside the allowlist
  //    (this is where geolocation / presence fields are refused → I-4 / I-6).
  for (const f of envelope.changed_fields) {
    if (!CONTACT_UPDATE_ALLOWED_FIELDS.has(f))
      throw new ContactUpdateRejected('field-not-allowed', f);
  }

  // 5) changed_fields must be an HONEST manifest of delta: exactly the delta's keys, no more, no less.
  //    Prevents signing a small declared change while smuggling other keys in delta.
  const deltaKeys = Object.keys(envelope.delta);
  const declared = new Set(envelope.changed_fields);
  for (const k of deltaKeys)
    if (!declared.has(k)) throw new ContactUpdateRejected('undeclared-delta-field', k);
  for (const f of envelope.changed_fields)
    if (!Object.prototype.hasOwnProperty.call(envelope.delta, f))
      throw new ContactUpdateRejected('declared-field-missing', f);

  // 5b) VALUE firewall for the structured method fields — a valid signature does NOT make an abusive
  //     map safe. The recipient fail-CLOSES on a malformed/oversized handles map or urls list BEFORE
  //     apply (defense-in-depth with apply + send-UI). Pre-crypto (cheap → DoS-resistant). Bounds are
  //     the shared CONTACT_HANDLE_KEYS + *_MAX constants (verify ≡ apply ≡ send-UI, single source).
  for (const f of envelope.changed_fields) {
    const v = envelope.delta[f];
    if (f === 'handles') {
      if (!isPlainObject(v)) throw new ContactUpdateRejected('field-value-invalid', 'handles must be an object');
      const hk = Object.keys(v);
      if (hk.length > HANDLES_MAX_COUNT)
        throw new ContactUpdateRejected('field-value-invalid', `handles count ${hk.length} > ${HANDLES_MAX_COUNT}`);
      for (const k of hk) {
        if (!CONTACT_HANDLE_KEYS.has(k)) throw new ContactUpdateRejected('field-value-invalid', `handle key: ${k}`);
        const hv = (v as Record<string, unknown>)[k];
        // Each handle value is a bounded string. Empty string '' = explicit removal (apply deletes the
        // key, per merge-semantics). null is NOT allowed — canonicalize forbids null in the signed form,
        // so a null could never have been legitimately signed; reject it here too.
        if (typeof hv !== 'string' || hv.length > HANDLE_VALUE_MAX_LEN)
          throw new ContactUpdateRejected('field-value-invalid', `handle value: ${k}`);
      }
    } else if (f === 'urls') {
      if (!Array.isArray(v)) throw new ContactUpdateRejected('field-value-invalid', 'urls must be an array');
      if (v.length > URLS_MAX_COUNT)
        throw new ContactUpdateRejected('field-value-invalid', `urls count ${v.length} > ${URLS_MAX_COUNT}`);
      for (const u of v)
        if (typeof u !== 'string' || u.length > URL_VALUE_MAX_LEN)
          throw new ContactUpdateRejected('field-value-invalid', 'url value');
    }
  }

  // 6) Optional suite floor for this contact.
  if (opts.requirePq && !signature.pq_signature)
    throw new ContactUpdateRejected('pq-required', 'hybrid signature required');

  // 7) Signature — DELEGATED to the 0.1 envelope primitive. Domain is pinned to DOMAIN_CONTACT_UPDATE
  //    (so a signature made for any other object type fails here), and the suite is derived inside the
  //    primitive from the signature shape (so a stripped-PQ downgrade fails). We never touch raw crypto.
  const ok = await verifyWithEnvelope(
    DOMAIN_CONTACT_UPDATE,
    contactUpdateSigningInput(envelope),
    signature,
    known.classicalPublicKeyArmored,
    known.pqSigningPublicKey,
  );
  if (!ok) throw new ContactUpdateRejected('bad-signature');

  return {
    fingerprint: envelope.fingerprint,
    epoch: envelope.epoch,
    version: envelope.version,
    changed_fields: [...envelope.changed_fields],
    delta: { ...envelope.delta },
  };
}

function isRotationAuth(auth: SuccessorAuth): auth is RotationSuccessorAuth {
  if (!auth || auth.kind !== 'rotation') return false;
  const a = auth as RotationSuccessorAuth;
  return (
    typeof a.sig_by_authority === 'string' &&
    !!a.auth_pubkeys &&
    typeof a.auth_pubkeys.sign === 'string' &&
    typeof a.auth_pubkeys.pq_sig === 'string'
  );
}

/**
 * Rotation successor as presented to the address-book verifier. Operational keys are
 * FRESH-RANDOM (not pre-committed); the authority signature authenticates them via
 * new_fingerprint, and Invariant-1 binds that fingerprint to the carried pubs.
 */
export interface RotationSuccessorInput {
  durable_id: string;
  prior_epoch: number;
  successor_epoch: number;
  new_fingerprint: string;
  new_public_key: string;
  new_pq_kem_public_key: string;
  new_pq_sig_public_key: string;
  /** Pin for the epoch AFTER this successor (the chain continues). */
  next_authority_commitment: string;
  auth: SuccessorAuth;
}

export interface AdoptedRotationIdentity {
  fingerprint: string;
  epoch: number;
  classicalPublicKeyArmored: string;
  next_authority_commitment: string;
}

/**
 * Verify a kind:'rotation' successor against the pre-committed authority pin.
 * On success, the caller adopts the returned identity (epoch, fingerprint, operational
 * key, next pin). Unknown kind FAIL-CLOSES. Field-updates with an ahead epoch still
 * throw epoch-ahead-needs-lineage from verifyIncomingContactUpdate — this is the
 * lineage-gated path that replaces that throw once a successor is in hand.
 */
export async function verifyRotationSuccessor(
  successor: RotationSuccessorInput,
  known: KnownContactIdentity,
): Promise<AdoptedRotationIdentity> {
  const auth = successor?.auth;
  if (!auth || typeof auth.kind !== 'string') {
    throw new ContactUpdateRejected('rotation-unknown-kind', 'missing successor kind');
  }
  // Open discriminant: anything other than the launch rotation kind FAIL-CLOSES.
  if (auth.kind !== 'rotation' || !isRotationAuth(auth)) {
    throw new ContactUpdateRejected('rotation-unknown-kind', String(auth.kind));
  }

  if (successor.durable_id !== known.fingerprint) {
    throw new ContactUpdateRejected('wrong-origin', `${successor.durable_id} != ${known.fingerprint}`);
  }
  if (successor.successor_epoch !== known.epoch + 1) {
    throw new ContactUpdateRejected(
      'rotation-epoch-not-next',
      `epoch ${successor.successor_epoch} !== ${known.epoch} + 1`,
    );
  }

  const pin = known.next_authority_commitment || '';
  let revealHash: string;
  try {
    revealHash = authorityCommitmentFromReveal(auth.auth_pubkeys.sign, auth.auth_pubkeys.pq_sig);
  } catch (e) {
    throw new ContactUpdateRejected(
      'rotation-commitment-mismatch',
      e instanceof Error ? e.message : 'reveal decode failed',
    );
  }
  if (revealHash !== pin) {
    throw new ContactUpdateRejected('rotation-commitment-mismatch', 'H(reveal) != next_authority_commitment');
  }

  const signingInput = rotationSigningInput({
    durable_id: successor.durable_id,
    prior_epoch: successor.prior_epoch,
    prior_authority_commitment: pin,
    successor_epoch: successor.successor_epoch,
    new_fingerprint: successor.new_fingerprint,
    next_authority_commitment: successor.next_authority_commitment,
  });
  const sigOk = verifyRotationAuthority(
    signingInput,
    auth.sig_by_authority,
    auth.auth_pubkeys.sign,
    auth.auth_pubkeys.pq_sig,
  );
  if (!sigOk) throw new ContactUpdateRejected('rotation-bad-authority-sig');

  const fpOk = await fingerprintMatchesKey(
    successor.new_fingerprint,
    successor.new_public_key,
    {
      kem_public_key: successor.new_pq_kem_public_key,
      sig_public_key: successor.new_pq_sig_public_key,
    },
  );
  if (!fpOk) {
    throw new ContactUpdateRejected(
      'rotation-fingerprint-mismatch',
      'new_fingerprint does not bind the new operational pubs',
    );
  }

  return {
    fingerprint: successor.new_fingerprint,
    epoch: successor.successor_epoch,
    classicalPublicKeyArmored: successor.new_public_key,
    next_authority_commitment: successor.next_authority_commitment,
  };
}
