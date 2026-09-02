// src/lib/trust/mutual-vouch.ts
// R1 remote mutual-VOUCH crypto — the TRUSTED-tier attestation (Peter's 3-state model #125308:
// KNOWN → VERIFIED → TRUSTED). Flint's crypto standalone; Athena's state machine composes mutuality.
//
// WHERE THIS SITS. KNOWN (joiner-response.ts) makes an invite connection mutual but UNVERIFIED.
// VERIFIED is the receiver's LOCAL out-of-band flag ("I checked this person's fingerprint in person / on
// a call") — no crypto, because the key is already bound at KNOWN. TRUSTED = VERIFIED **and MUTUAL**:
// both parties have verified each other AND each has told the other so. This module is the crypto for
// "telling the other so" over the network: once you've VERIFIED a contact, you sign a vouch and deposit
// it (per-peer-encrypted) to their mailbox. When BOTH directions exist, the edge is TRUSTED.
//
// MUTUALITY IS COMPOSED CALLER-SIDE, NOT HERE. This module produces and verifies ONE DIRECTIONAL vouch
// ("voucher attests they verified vouchee"). The state machine (Athena) declares TRUSTED when it holds
// BOTH (a) our own local "I verified + vouched for them" AND (b) a verifyVouch()-accepted inbound vouch
// FROM them. Keeping mutuality out of the crypto means the crypto stays a small, total function and the
// UI owns the (revocable, user-visible) trust state. In-person mutual QR/NFC grants TRUSTED atomically
// and needs no wire at all; this is the REMOTE path.
//
// NOT TOFU — THE KEY DIFFERENCE FROM joiner-response. A joiner-response is from someone we have never
// met, so it is self-asserted (verified against the key IN the envelope + fingerprintMatchesKey). A
// vouch is from a contact we ALREADY HOLD (they are at least KNOWN — we have their key). So a vouch
// carries NO public key: it is verified against the key we already hold for that fingerprint, supplied
// by the REQUIRED `lookupVoucher` oracle. A vouch from a fingerprint we do not hold is refused — you
// cannot be vouched-for by a stranger. This is exactly "bind first, verify against the bound key" — the
// vouch cannot introduce or rotate a key (that is key.rotate's lineage-gated path, never a vouch).
//
// BINDINGS (what the signature covers, so none can be swapped on the wire):
//   • voucher_fingerprint — who is vouching. Verified against the HELD key for this fp (not self-asserted).
//   • voucher_epoch       — the voucher's key epoch. Must equal the epoch we hold; a newer epoch means
//                           run key-lineage catch-up first, then retry (we can't verify against a key we
//                           don't have). Mirrors contact-update's epoch floor.
//   • vouchee_fingerprint — MUST equal OUR own fingerprint. Binds the vouch to its intended recipient so
//                           a copied vouch blob can't be replayed into a third party's mailbox as a vouch
//                           "for them".
// IDEMPOTENT, NOT single-use. A vouch is a durable positive attestation, so replay is harmless (it
// re-asserts the same edge). The recipient tracks the latest `ts` per voucher for freshness; VOUCH
// REVOCATION (a voucher later withdrawing) is a deliberate FOLLOW-UP, not launch — a revoke needs its
// own signed object (a replayed pre-revocation vouch must not silently re-assert TRUSTED). Flagged so
// the state machine treats TRUSTED as revocable UI state, not a crypto-permanent fact.
//
// FAIL-CLOSED / SILENT-DROP (I-1/I-2). verifyVouch returns VerifiedVouch | null and NEVER throws — the
// mailbox is an open channel carrying joiner-responses, contact-updates, vouches, and noise; a
// non-matching blob drops silently (no reason leak, no crash). `lookupVoucher` is REQUIRED so a vouch
// can never be accepted from a non-contact by an eager caller.

import {
  DOMAIN_MUTUAL_VOUCH,
  mutualVouchSigningInput,
  type MutualVouchEnvelope,
} from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import {
  createMessage,
  encrypt,
  readKey,
  readPrivateKey,
  decryptKey,
  readMessage,
  decrypt,
} from 'openpgp';

/** A vouch as it travels: the envelope plus its detached envelope signature (opaque on the wire). */
export interface SignedVouch {
  envelope: MutualVouchEnvelope;
  signature: EnvelopeSignature;
}

/** The held identity of a voucher — supplied by the caller's lookupVoucher oracle. A vouch is verified
 *  against THIS key (not a key in the envelope); if the caller does not hold the voucher, the lookup
 *  returns null and the vouch is refused. */
export interface KnownVoucher {
  /** The epoch whose key we currently hold for this voucher (must match the vouch's voucher_epoch). */
  epoch: number;
  /** Armored classical public key we hold for the voucher at `epoch`. */
  publicKeyArmored: string;
  /** ML-DSA public key half, iff we require/accept the hybrid suite for this voucher. */
  pqSigningPublicKey?: Uint8Array;
}

/** A vouch that passed every check — the caller MAY now record "voucher vouches for us" (one direction
 *  of mutuality). */
export interface VerifiedVouch {
  voucherFingerprint: string;
  voucherEpoch: number;
  voucheeFingerprint: string;
  ts: string;
}

/** Thrown at BUILD time (send side controls its own inputs) — fail loud for the SENDER. */
export class VouchSignError extends Error {
  constructor(
    public readonly reason: 'bad-voucher-fingerprint' | 'bad-voucher-epoch' | 'bad-vouchee-fingerprint',
    detail?: string,
  ) {
    super(detail ? `vouch build refused (${reason}): ${detail}` : `vouch build refused (${reason})`);
    this.name = 'VouchSignError';
  }
}

export interface BuildVouchArgs {
  /** The voucher's durable fingerprint (the sender — must be a contact the vouchee already holds). */
  voucherFp: string;
  /** The voucher's current key epoch — the vouchee verifies against the key it holds at this epoch. */
  voucherEpoch: number;
  /** The vouchee's durable fingerprint (the recipient). Binds the vouch to them. */
  voucheeFp: string;
  /** ISO-8601 UTC; audit/display + freshness ONLY. Inject for deterministic tests. */
  ts?: string;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Build a well-formed MutualVouchEnvelope, enforcing the structural rules verify relies on. */
export function buildVouchEnvelope(args: BuildVouchArgs): MutualVouchEnvelope {
  if (!isNonEmptyString(args.voucherFp)) throw new VouchSignError('bad-voucher-fingerprint');
  if (!Number.isSafeInteger(args.voucherEpoch) || args.voucherEpoch < 0)
    throw new VouchSignError('bad-voucher-epoch', String(args.voucherEpoch));
  if (!isNonEmptyString(args.voucheeFp)) throw new VouchSignError('bad-vouchee-fingerprint');
  return {
    voucher_fingerprint: args.voucherFp,
    voucher_epoch: args.voucherEpoch,
    vouchee_fingerprint: args.voucheeFp,
    ts: args.ts ?? new Date().toISOString(),
  };
}

/**
 * Sign a MutualVouchEnvelope → SignedVouch. EXACT mirror of the verify path (same DOMAIN_MUTUAL_VOUCH +
 * mutualVouchSigningInput). pqSigningSecretKey ⇒ hybrid suite (bound inside → anti-downgrade). Signs
 * whatever envelope it is given — use buildVouch for the structural guarantees.
 */
export async function signVouch(
  envelope: MutualVouchEnvelope,
  voucherPrivateKeyArmored: string,
  passphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedVouch> {
  const signature = await signWithEnvelope(
    DOMAIN_MUTUAL_VOUCH,
    mutualVouchSigningInput(envelope),
    voucherPrivateKeyArmored,
    passphrase,
    pqSigningSecretKey,
  );
  return { envelope, signature };
}

/** The common send path: build (with structural guarantees) AND sign in one call. */
export async function buildVouch(
  args: BuildVouchArgs,
  voucherPrivateKeyArmored: string,
  passphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedVouch> {
  return signVouch(buildVouchEnvelope(args), voucherPrivateKeyArmored, passphrase, pqSigningSecretKey);
}

/** Send side: encrypt a signed vouch to the VOUCHEE's public key → opaque armored blob (relay can't
 *  read the trust edge — I-1). Mirrors encryptContactUpdateTo / encryptJoinerResponseTo. */
export async function encryptVouchTo(
  signed: SignedVouch,
  voucheePublicKeyArmored: string,
): Promise<string> {
  const encryptionKeys = await readKey({ armoredKey: voucheePublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(signed) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/** Narrow structural check on a decrypted candidate — must have the shape of a vouch (demuxes a vouch
 *  from a joiner-response / contact-update / noise sharing the mailbox). */
function isWellFormed(signed: unknown): signed is SignedVouch {
  if (!isPlainObject(signed)) return false;
  const { envelope, signature } = signed as Record<string, unknown>;
  if (!isPlainObject(envelope)) return false;
  const e = envelope as Record<string, unknown>;
  if (!isNonEmptyString(e.voucher_fingerprint)) return false;
  if (typeof e.voucher_epoch !== 'number' || !Number.isSafeInteger(e.voucher_epoch) || e.voucher_epoch < 0)
    return false;
  if (!isNonEmptyString(e.vouchee_fingerprint)) return false;
  if (typeof e.ts !== 'string') return false;
  if (!isPlainObject(signature)) return false;
  if (typeof (signature as Record<string, unknown>).classical !== 'string') return false;
  return true;
}

async function decryptVouchBlob(
  blob: string,
  voucheePrivateKeyArmored: string,
  passphrase: string,
): Promise<SignedVouch | null> {
  try {
    const locked = await readPrivateKey({ armoredKey: voucheePrivateKeyArmored });
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
 * CONSUME side: verify an inbound vouch and return the verified attestation — or null (silent drop).
 * THE ONLY WAY to obtain a {@link VerifiedVouch}. Order is cheap→crypto (open mailbox → DoS resistance):
 *   1. decrypt to our key (unavoidably first — E2E to the vouchee); wrong-recipient → null
 *   2. structural well-formedness (in decrypt); a joiner-response/contact-update/noise blob → null
 *   3. vouchee-binding: envelope.vouchee_fingerprint === OUR fp (no cross-recipient replay)   [cheap]
 *   4. lookupVoucher(voucher_fingerprint) — must be a contact WE ALREADY HOLD (not TOFU)      [cheap]
 *   5. epoch: voucher_epoch === the epoch we hold (else lineage catch-up first, then retry)   [cheap]
 *   6. suite floor (opts.requirePq) then the SIGNATURE against the HELD voucher key            [expensive, last]
 *
 * @param lookupVoucher REQUIRED. `(voucherFp) => KnownVoucher | null`: the held key material for that
 *   contact, or null if we do not hold them. Required so a vouch can never be accepted from a stranger.
 */
export async function verifyVouch(
  blob: string,
  vouchee: { fingerprint: string; privateKeyArmored: string; passphrase: string },
  lookupVoucher: (voucherFp: string) => KnownVoucher | null,
  opts: { requirePq?: boolean } = {},
): Promise<VerifiedVouch | null> {
  const signed = await decryptVouchBlob(blob, vouchee.privateKeyArmored, vouchee.passphrase);
  if (!signed) return null;
  const { envelope, signature } = signed;

  // 3) Vouchee-binding — the vouch must be addressed to US.
  if (envelope.vouchee_fingerprint.toUpperCase() !== vouchee.fingerprint.toUpperCase()) return null;

  // 4) The voucher must be a contact we already hold (not TOFU). A throwing oracle fails closed.
  let known: KnownVoucher | null;
  try {
    known = lookupVoucher(envelope.voucher_fingerprint);
  } catch {
    return null;
  }
  if (!known || !isNonEmptyString(known.publicKeyArmored)) return null;

  // 5) Epoch: we can only verify against the key we hold, which is valid at known.epoch. A newer epoch
  //    means the voucher rotated — the caller must run lineage catch-up, update `known`, then retry.
  if (envelope.voucher_epoch !== known.epoch) return null;

  // 6) Suite floor + signature against the HELD key (NOT self-asserted → no fingerprintMatchesKey).
  if (opts.requirePq && !signature.pq_signature) return null;
  let ok = false;
  try {
    ok = await verifyWithEnvelope(
      DOMAIN_MUTUAL_VOUCH,
      mutualVouchSigningInput(envelope),
      signature,
      known.publicKeyArmored,
      known.pqSigningPublicKey,
    );
  } catch {
    return null;
  }
  if (!ok) return null;

  return {
    voucherFingerprint: envelope.voucher_fingerprint,
    voucherEpoch: envelope.voucher_epoch,
    voucheeFingerprint: envelope.vouchee_fingerprint,
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
