// src/lib/trust/joiner-response.ts
// R1 pending-joiner RETURN-CHANNEL crypto — the KNOWN-tier handshake that closes the one-directional
// Grow asymmetry (Peter #125331). This is Flint's crypto standalone; Athena wires the deposit
// (JoinerCeremony persistEdge), the consume (live-book-poll), and the 3-state machine around it.
//
// THE BUG THIS FIXES. Alice (giver) shares a Grow card via a relay code / QR. Bob (joiner) imports it
// and adds Alice — but the flow is ONE-DIRECTIONAL: Alice never learns Bob added her, so the edge is
// not mutual, so the already-live contact.update wire (0.4) has no Bob-edge to propagate along ("no
// connect → no send", Peter #125331). This module is the RETURN CHANNEL: after Bob adds Alice, Bob
// signs a self-asserted identity claim and deposits it (per-peer-encrypted) to Alice's mailbox; Alice
// verifies it and surfaces Bob as KNOWN. Now the edge is mutual and methods flow both ways over 0.4.
//
// THE TRUST TIER — KNOWN (Peter #125308, the authoritative 3-state model KNOWN→VERIFIED→TRUSTED).
// A joiner-response yields KNOWN: added-but-UNVERIFIED, self-asserted TOFU. We do NOT — and cannot —
// authenticate WHO Bob is against anything we already hold (we've never met Bob). What we CAN and DO
// enforce is that the claim is SELF-CONSISTENT and SOLICITED:
//   (a) SELF-CONSISTENT — joiner_fingerprint === H(joiner_public_key) (Invariant-1, fingerprintMatchesKey)
//       AND the envelope signature verifies against joiner_public_key. Bob proves possession of the
//       private key behind the fingerprint+name he claims. (This is TOFU: trust the key on first use.)
//   (b) SOLICITED — invite_nonce is one of the giver's OWN OUTSTANDING relay codes (the caller's
//       `acceptNonce` oracle). Without this an open mailbox is an unsolicited-contact (spam) firehose:
//       anyone could deposit "add me". The nonce proves the sender used THIS giver's invite.
//       MULTI-USE, NOT single-use: a Grow link is shared with N people, so ONE code legitimately yields
//       N joiner-responses. So the code is NEVER "consumed" on first use — the oracle is a MEMBERSHIP
//       test (code ∈ outstanding-and-unexpired), and anti-replay/anti-spam is per-(code, joinerFp): the
//       oracle receives BOTH the nonce and the (claimed) joiner fingerprint so the caller's store can
//       (i) accept each distinct joiner at most once per code and (ii) cap distinct joiners per code
//       (GROW_INVITE_CAP). Same-joiner replay of a captured blob is dropped by that per-(code,joinerFp)
//       dedup AND is idempotent at apply (contacts dedup by fingerprint). KNOWN-tier property
//       (documented, not a flaw): whoever holds a live, uncapped invite code can connect as KNOWN —
//       codes are high-entropy + expiring; VERIFIED still requires an out-of-band human check, TRUSTED
//       requires mutual vouch (see mutual-vouch.ts).
//   (c) NOT REPLAYABLE ACROSS GIVERS — giver_fingerprint is signed and checked === our own fp, so a
//       copied blob re-deposited to a different giver's mailbox is rejected there.
//
// IDENTITY-ONLY BY DESIGN. The envelope carries the joiner's identity (fp, epoch, key, optional PQ sig
// key, name) — NOT their contact methods. Once the edge is mutual, the giver holds the joiner's card
// and the 0.4 contact.update wire carries methods both ways. Keeping methods out of here means the
// joiner-response inherits NO field-firewall surface — the entire method-poisoning surface stays on
// the one already-hardened path (contact-update.ts), not duplicated here.
//
// CORRECT-BY-CONSTRUCTION. Like contact-update-sign.ts and identity-card-sign.ts, this reuses the SAME
// three primitives every verifier reads and re-implements none of them: the domain tag
// DOMAIN_JOINER_RESPONSE (domain separation — a joiner-response sig can't verify as a contact-update /
// identity-card), the signing input joinerResponseSigningInput (canonicalize — byte-drift impossible),
// and the 0.1 envelope sign/verify (suite bound INSIDE the signature → anti-downgrade for free). The
// E2E envelope mirrors contact-update-envelope.ts (classical openpgp, opaque to the relay, recipient-
// only decrypt). fingerprintMatchesKey is the shared Invariant-1 check (case-robust, never throws).
//
// FAIL-CLOSED / SILENT-DROP (I-1/I-2). verifyJoinerResponse returns PendingJoiner | null and NEVER
// throws: the mailbox is an OPEN channel that also carries contact-updates and outright noise, so a
// non-matching or malformed blob must drop silently (no reason leak to a depositor, no crash on
// garbage) — exactly the null-on-any-failure contract of openpgpEnvelopeDecryptor. There is no way to
// obtain a PendingJoiner except through the full check, and `acceptNonce` is a REQUIRED argument, so
// the solicited-gate cannot be skipped by an eager caller.

import {
  DOMAIN_JOINER_RESPONSE,
  joinerResponseSigningInput,
  type JoinerResponseEnvelope,
} from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import { fingerprintMatchesKey } from '../identity/fingerprint';
import { base64ToUint8 } from '../crypto/pq';
import {
  createMessage,
  encrypt,
  readKey,
  readPrivateKey,
  decryptKey,
  readMessage,
  decrypt,
} from 'openpgp';

/** A joiner-response as it travels: the envelope plus its detached envelope signature (opaque on the wire). */
export interface SignedJoinerResponse {
  envelope: JoinerResponseEnvelope;
  signature: EnvelopeSignature;
}

/**
 * The verified, self-asserted joiner surfaced to the giver as KNOWN. Shaped to seed the giver's
 * contact record directly: {fingerprint, epoch, classicalPublicKeyArmored: publicKeyArmored,
 * pqSigningPublicKey} is exactly a KnownContactIdentity (with version seeded to 0 by the caller), and
 * `inviteNonce` is handed back so the caller can mark it consumed (single-use).
 */
export interface PendingJoiner {
  fingerprint: string;
  epoch: number;
  publicKeyArmored: string;
  pqSigningPublicKey?: Uint8Array;
  displayName: string;
  inviteNonce: string;
  ts: string;
}

/** Thrown at BUILD time (send side) when a caller tries to build a structurally invalid response —
 *  fail loud for the SENDER, who controls its own inputs (contrast verify, which drops silently). */
export class JoinerResponseSignError extends Error {
  constructor(
    public readonly reason:
      | 'bad-joiner-fingerprint'
      | 'bad-joiner-epoch'
      | 'bad-joiner-public-key'
      | 'bad-joiner-name'
      | 'bad-giver-fingerprint'
      | 'bad-invite-nonce'
      | 'bad-pq-key',
    detail?: string,
  ) {
    super(detail ? `joiner-response build refused (${reason}): ${detail}` : `joiner-response build refused (${reason})`);
    this.name = 'JoinerResponseSignError';
  }
}

export interface BuildJoinerResponseArgs {
  /** The joiner's durable, genesis-derived fingerprint (the sender of the response). */
  joinerFp: string;
  /** The joiner's current key epoch — the giver records it as the future contact.update floor. */
  joinerEpoch: number;
  /** The joiner's armored classical public key — the giver adds it AND the signature verifies against it. */
  joinerPubKeyArmored: string;
  /** base64(ML-DSA-87 pubkey); pass iff signing hybrid. Bound by the classical signature (anti-swap). */
  joinerPqSigPublicKey?: string;
  /** The joiner's self-asserted display name (KNOWN = unverified; may be empty). */
  joinerName: string;
  /** The giver's durable fingerprint — binds the response to its intended recipient. */
  giverFp: string;
  /** The giver's relay code the joiner used — the solicited-gate proof. */
  inviteNonce: string;
  /** ISO-8601 UTC; audit/display ONLY. Inject for deterministic tests. */
  ts?: string;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Build a well-formed JoinerResponseEnvelope, enforcing the structural rules the verifier relies on.
 * The optional PQ sig key is OMITTED (not set undefined/null) when absent — canonical serialization
 * rejects null, so sign and verify must both operate on an object that simply lacks the key.
 */
export function buildJoinerResponseEnvelope(args: BuildJoinerResponseArgs): JoinerResponseEnvelope {
  if (!isNonEmptyString(args.joinerFp)) throw new JoinerResponseSignError('bad-joiner-fingerprint');
  if (!Number.isSafeInteger(args.joinerEpoch) || args.joinerEpoch < 0)
    throw new JoinerResponseSignError('bad-joiner-epoch', String(args.joinerEpoch));
  if (!isNonEmptyString(args.joinerPubKeyArmored)) throw new JoinerResponseSignError('bad-joiner-public-key');
  if (typeof args.joinerName !== 'string') throw new JoinerResponseSignError('bad-joiner-name');
  if (!isNonEmptyString(args.giverFp)) throw new JoinerResponseSignError('bad-giver-fingerprint');
  if (!isNonEmptyString(args.inviteNonce)) throw new JoinerResponseSignError('bad-invite-nonce');
  if (args.joinerPqSigPublicKey !== undefined && !isNonEmptyString(args.joinerPqSigPublicKey))
    throw new JoinerResponseSignError('bad-pq-key', 'present but empty');

  const env: JoinerResponseEnvelope = {
    joiner_fingerprint: args.joinerFp,
    joiner_epoch: args.joinerEpoch,
    joiner_public_key: args.joinerPubKeyArmored,
    joiner_display_name: args.joinerName,
    giver_fingerprint: args.giverFp,
    invite_nonce: args.inviteNonce,
    ts: args.ts ?? new Date().toISOString(),
  };
  if (args.joinerPqSigPublicKey !== undefined) env.joiner_pq_sig_public_key = args.joinerPqSigPublicKey;
  return env;
}

/**
 * Sign a JoinerResponseEnvelope → a SignedJoinerResponse. EXACT mirror of the verify path (same
 * DOMAIN_JOINER_RESPONSE + joinerResponseSigningInput). Passing pqSigningSecretKey selects the hybrid
 * suite (the signature carries pq_signature; the suite is bound inside → stripping it fails verify).
 * NOTE: signs whatever envelope it is given — build via buildJoinerResponseEnvelope (or the combined
 * buildJoinerResponse) for the structural guarantees. If hybrid, joiner_pq_sig_public_key MUST be in
 * the envelope or the recipient cannot verify the PQ half.
 */
export async function signJoinerResponse(
  envelope: JoinerResponseEnvelope,
  joinerPrivateKeyArmored: string,
  passphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedJoinerResponse> {
  const signature = await signWithEnvelope(
    DOMAIN_JOINER_RESPONSE,
    joinerResponseSigningInput(envelope),
    joinerPrivateKeyArmored,
    passphrase,
    pqSigningSecretKey,
  );
  return { envelope, signature };
}

/**
 * The common send path: build (with structural guarantees) AND sign in one call. This is the function
 * the joiner side (JoinerCeremony persistEdge) calls after adding the giver.
 */
export async function buildJoinerResponse(
  args: BuildJoinerResponseArgs,
  joinerPrivateKeyArmored: string,
  passphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedJoinerResponse> {
  return signJoinerResponse(
    buildJoinerResponseEnvelope(args),
    joinerPrivateKeyArmored,
    passphrase,
    pqSigningSecretKey,
  );
}

/**
 * Send side: encrypt a signed joiner-response to the GIVER's public key → opaque armored blob. The
 * relay stores it opaquely (custody §4 / I-1); only the giver's private key decrypts. Mirrors
 * encryptContactUpdateTo — same classical openpgp E2E, no new key material.
 */
export async function encryptJoinerResponseTo(
  signed: SignedJoinerResponse,
  giverPublicKeyArmored: string,
): Promise<string> {
  const encryptionKeys = await readKey({ armoredKey: giverPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(signed) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/** Narrow structural check on a decrypted candidate — must have the shape of a joiner-response
 *  BEFORE any field logic. A contact-update blob (or noise) fails here → the caller's null (this is
 *  also how a mixed mailbox is demultiplexed: the wrong type structurally mismatches). */
function isWellFormed(signed: unknown): signed is SignedJoinerResponse {
  if (!isPlainObject(signed)) return false;
  const { envelope, signature } = signed as Record<string, unknown>;
  if (!isPlainObject(envelope)) return false;
  const e = envelope as Record<string, unknown>;
  if (!isNonEmptyString(e.joiner_fingerprint)) return false;
  if (typeof e.joiner_epoch !== 'number' || !Number.isSafeInteger(e.joiner_epoch) || e.joiner_epoch < 0)
    return false;
  if (!isNonEmptyString(e.joiner_public_key)) return false;
  if (typeof e.joiner_display_name !== 'string') return false;
  if (!isNonEmptyString(e.giver_fingerprint)) return false;
  if (!isNonEmptyString(e.invite_nonce)) return false;
  if (typeof e.ts !== 'string') return false;
  // Optional PQ key: if present it must be a non-empty string (never null — canonical would reject it).
  if (e.joiner_pq_sig_public_key !== undefined && !isNonEmptyString(e.joiner_pq_sig_public_key)) return false;
  if (!isPlainObject(signature)) return false;
  if (typeof (signature as Record<string, unknown>).classical !== 'string') return false;
  return true;
}

/** Decrypt an opaque blob to a SignedJoinerResponse candidate, or null on ANY failure (not-for-us /
 *  corrupt / wrong key / not-JSON / wrong-shape). Mirrors openpgpEnvelopeDecryptor. */
async function decryptJoinerBlob(
  blob: string,
  giverPrivateKeyArmored: string,
  passphrase: string,
): Promise<SignedJoinerResponse | null> {
  try {
    const locked = await readPrivateKey({ armoredKey: giverPrivateKeyArmored });
    const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
    const message = await readMessage({ armoredMessage: blob });
    const { data } = await decrypt({ message, decryptionKeys });
    const text = typeof data === 'string' ? data : await streamToText(data);
    const parsed = JSON.parse(text) as unknown;
    return isWellFormed(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * CONSUME side: verify an inbound joiner-response and return the KNOWN joiner — or null (silent drop).
 * THIS IS THE ONLY WAY to obtain a {@link PendingJoiner}; every gate must pass. Order is cheap→crypto
 * for DoS resistance (a mailbox is open — garbage must not burn signature CPU):
 *   1. decrypt to our key (unavoidably first — the blob is E2E to the giver); wrong-recipient → null
 *   2. structural well-formedness (in decrypt); a contact-update/noise blob → null
 *   3. giver-binding: envelope.giver_fingerprint === our own fp (no cross-giver replay)  [cheap]
 *   4. solicited-gate: acceptNonce(invite_nonce) — the caller's issued+unconsumed oracle             [cheap]
 *   5. Invariant-1: fingerprintMatchesKey(joiner_fp, joiner_public_key)                              [medium]
 *   6. suite floor (opts.requirePq) then the envelope SIGNATURE against joiner_public_key (TOFU)      [expensive, last]
 * Steps 3–4 read the not-yet-sig-verified envelope as a cheap pre-filter; step 6 then confirms every
 * one of those fields was bound by the signature, so a tampered giver_fingerprint/invite_nonce fails.
 *
 * ANTI-REPLAY / MULTI-USE is the caller's to complete: after a NON-null return, record the pair
 * (result.inviteNonce, result.fingerprint) as accepted in the issued-code store (do the acceptNonce
 * check + record atomically to close the TOCTOU). The CODE is NEVER consumed (a Grow link is multi-use);
 * only the (code, joiner) pair is — so joiners #2..N on a shared link still connect, while a replayed
 * blob from an already-accepted joiner is dropped at step 4 next time.
 *
 * @param acceptNonce REQUIRED. `(nonce, joinerFp) => boolean`: true iff `nonce` is one of OUR
 *   outstanding (issued, unexpired, under GROW_INVITE_CAP) relay codes AND this `joinerFp` has not
 *   already been accepted on it. Receives the CLAIMED joiner fingerprint (pre-signature — a false claim
 *   only hurts the claimant, since steps 5/6 then require a self-consistent, validly-signed identity).
 *   Required (not optional) so the solicited-gate can never be skipped by an eager caller.
 */
export async function verifyJoinerResponse(
  blob: string,
  giver: { fingerprint: string; privateKeyArmored: string; passphrase: string },
  acceptNonce: (nonce: string, joinerFp: string) => boolean,
  opts: { requirePq?: boolean } = {},
): Promise<PendingJoiner | null> {
  const signed = await decryptJoinerBlob(blob, giver.privateKeyArmored, giver.passphrase);
  if (!signed) return null;
  const { envelope, signature } = signed;

  // 3) Giver-binding — the response must be addressed to US. Case-insensitive like fingerprintMatchesKey.
  if (envelope.giver_fingerprint.toUpperCase() !== giver.fingerprint.toUpperCase()) return null;

  // 4) Solicited-gate — the invite_nonce must be one of our outstanding codes AND this (claimed) joiner
  //    must not already be accepted on it (multi-use per code, once per joiner). Cheap pre-filter.
  let nonceOk = false;
  try {
    nonceOk = acceptNonce(envelope.invite_nonce, envelope.joiner_fingerprint) === true;
  } catch {
    return null; // a throwing oracle is treated as reject (fail-closed)
  }
  if (!nonceOk) return null;

  // 5) Invariant-1 — the self-asserted fingerprint must actually hash to the presented key.
  if (!(await fingerprintMatchesKey(envelope.joiner_fingerprint, envelope.joiner_public_key))) return null;

  // 6) Suite floor + signature (TOFU: verified against the key IN the envelope). requirePq rejects a
  //    classical-only response; otherwise classical-only is accepted (transition-era v1 joiners).
  if (opts.requirePq && !signature.pq_signature) return null;

  let pqSigningPublicKey: Uint8Array | undefined;
  if (envelope.joiner_pq_sig_public_key !== undefined) {
    try {
      pqSigningPublicKey = base64ToUint8(envelope.joiner_pq_sig_public_key);
    } catch {
      return null; // malformed PQ key → cannot verify → drop
    }
  }
  // A hybrid signature with NO PQ key in the envelope cannot be verified — fail closed.
  if (signature.pq_signature && !pqSigningPublicKey) return null;

  let ok = false;
  try {
    ok = await verifyWithEnvelope(
      DOMAIN_JOINER_RESPONSE,
      joinerResponseSigningInput(envelope),
      signature,
      envelope.joiner_public_key,
      pqSigningPublicKey,
    );
  } catch {
    return null;
  }
  if (!ok) return null;

  return {
    fingerprint: envelope.joiner_fingerprint,
    epoch: envelope.joiner_epoch,
    publicKeyArmored: envelope.joiner_public_key,
    ...(pqSigningPublicKey ? { pqSigningPublicKey } : {}),
    displayName: envelope.joiner_display_name,
    inviteNonce: envelope.invite_nonce,
    ts: envelope.ts,
  };
}

async function streamToText(data: unknown): Promise<string> {
  const maybe = data as { getReader?: () => ReadableStreamDefaultReader };
  if (typeof maybe?.getReader !== 'function') return String(data);
  const reader = maybe.getReader();
  const dec = new TextDecoder();
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out += typeof value === 'string' ? value : dec.decode(value as BufferSource, { stream: true });
  }
  return out;
}
