// src/lib/trust/contact-update-sign.ts
// 0.4 contact.update SEND-SIGN side — the exact mirror of contact-update.ts's CONSUME-VERIFY floor.
// This is the SENDER half of the "living address book": the card owner edits a method (new phone,
// new email, new display name / note), signs a delta, and it propagates to everyone who holds their
// card. This module does ONLY the sign; per-recipient encrypt + mailbox deposit is the wire on top
// (sync/contact-update-envelope.ts + the relay mailbox) and is deliberately kept OUT of here so the
// signing crypto stays unit-testable without a network.
//
// CORRECT-BY-CONSTRUCTION (the reason this file is safe to add). It produces a SignedContactUpdate
// that verifyIncomingContactUpdate ACCEPTS, because it reuses the SAME three primitives the verifier
// reads and never re-implements any of them:
//   • the SAME domain tag       DOMAIN_CONTACT_UPDATE       (domain-separation: a contact.update
//     signature can't verify as a trust-signal / slug-claim, and vice-versa — inherited, not re-added)
//   • the SAME signing input    contactUpdateSigningInput   (canonicalize(env), the exact preimage
//     verify recomputes — so a byte-drift between sign and verify is impossible)
//   • the SAME field firewall    CONTACT_UPDATE_ALLOWED_FIELDS (imported from the verify module, so
//     the send-side allowlist can NEVER diverge from the verify-side one — one Set, two callers)
// Passing pqSigningSecretKey selects the hybrid suite; the suite is bound INSIDE the signature by the
// 0.1 primitive (anti-downgrade — stripping the PQ half flips the derived suite and verification fails).
//
// FAIL-LOUD-AT-SEND. buildContactUpdateEnvelope enforces the verifier's structural rules at BUILD time
// (allowlist + honest manifest) so a sender can never mint an update that every recipient would silently
// drop (I-1/I-2: rejections are silent to the sender, so a bad send would just vanish — we refuse it
// here, loudly, instead). Version monotonicity is the RECIPIENT's floor (each holds their own last-seen);
// the caller supplies the new card version and we only reject structurally-invalid values.

import {
  DOMAIN_CONTACT_UPDATE,
  contactUpdateSigningInput,
  type ContactUpdateEnvelope,
} from '../format/envelope';
import { signWithEnvelope } from '../crypto/sign-envelope';
import { CONTACT_UPDATE_ALLOWED_FIELDS, type SignedContactUpdate } from './contact-update';

/**
 * Thrown when a caller tries to build an update the verifier would reject — the send-side twin of
 * ContactUpdateRejected. Fail LOUD at build time rather than ship an update that silently vanishes at
 * every recipient (I-1/I-2 make a rejected send invisible to the sender).
 */
export class ContactUpdateSignError extends Error {
  constructor(
    public readonly reason:
      | 'bad-fingerprint'
      | 'bad-epoch'
      | 'bad-version'
      | 'bad-delta'
      | 'empty-delta'
      | 'field-not-allowed',
    detail?: string,
  ) {
    super(detail ? `contact.update sign refused (${reason}): ${detail}` : `contact.update sign refused (${reason})`);
    this.name = 'ContactUpdateSignError';
  }
}

export interface BuildContactUpdateArgs {
  /** The card owner's durable, genesis-derived fingerprint (the sender). */
  fingerprint: string;
  /** The sender's current key epoch — receivers verify lineage against it. */
  epoch: number;
  /** The NEW monotonic card version. Caller increments per edit; each recipient enforces > their last-seen. */
  version: number;
  /** Only the changed fields. Keys MUST be within CONTACT_UPDATE_ALLOWED_FIELDS (firewall). */
  delta: Record<string, unknown>;
  /** ISO-8601 UTC; audit/display ONLY (never the ordering key — clocks lie). Inject for determinism. */
  updated_at?: string;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Build a well-formed ContactUpdateEnvelope, enforcing the SAME rules verifyIncomingContactUpdate
 * enforces so the result is guaranteed acceptable (not silently dropped):
 *   - every delta key ∈ CONTACT_UPDATE_ALLOWED_FIELDS (the I-4/I-6 field firewall)
 *   - changed_fields is derived from delta's keys → honest manifest by construction (no smuggling,
 *     no dishonest declaration; the two mismatch rejections in verify are unreachable for our output)
 *   - fingerprint/epoch/version are structurally valid (safe non-negative integers; non-empty fp)
 */
export function buildContactUpdateEnvelope(args: BuildContactUpdateArgs): ContactUpdateEnvelope {
  const { fingerprint, epoch, version, delta } = args;
  if (typeof fingerprint !== 'string' || fingerprint.length === 0)
    throw new ContactUpdateSignError('bad-fingerprint');
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new ContactUpdateSignError('bad-epoch', String(epoch));
  if (!Number.isSafeInteger(version) || version < 0)
    throw new ContactUpdateSignError('bad-version', String(version));
  if (!isPlainObject(delta)) throw new ContactUpdateSignError('bad-delta', 'not a plain object');

  const changed_fields = Object.keys(delta);
  if (changed_fields.length === 0) throw new ContactUpdateSignError('empty-delta');
  for (const f of changed_fields) {
    if (!CONTACT_UPDATE_ALLOWED_FIELDS.has(f)) throw new ContactUpdateSignError('field-not-allowed', f);
  }

  return {
    fingerprint,
    epoch,
    version,
    updated_at: args.updated_at ?? new Date().toISOString(),
    changed_fields,
    delta,
  };
}

/**
 * Sign a ContactUpdateEnvelope → a SignedContactUpdate the recipient's verifyIncomingContactUpdate
 * accepts. EXACT mirror of the verify path (same DOMAIN_CONTACT_UPDATE + contactUpdateSigningInput).
 * pqSigningSecretKey ⇒ hybrid suite (signature carries pq_signature); classical-only otherwise.
 *
 * NOTE: this signs whatever envelope it is given — use buildContactUpdateEnvelope (or buildAndSign)
 * to get the firewall/honest-manifest guarantees. Signing a hand-built envelope that violates them
 * produces a signature that verifies cryptographically but is rejected by verify's field firewall.
 */
export async function signContactUpdate(
  envelope: ContactUpdateEnvelope,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedContactUpdate> {
  const signature = await signWithEnvelope(
    DOMAIN_CONTACT_UPDATE,
    contactUpdateSigningInput(envelope),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
  );
  return { envelope, signature };
}

/**
 * The common sender path: build (with the firewall + honest-manifest guarantees) AND sign in one call.
 * One SignedContactUpdate is produced per card version; the wire then encrypts it per-recipient and
 * deposits — the signature is over the envelope, so it is identical for every recipient.
 */
export async function buildAndSignContactUpdate(
  args: BuildContactUpdateArgs,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedContactUpdate> {
  return signContactUpdate(
    buildContactUpdateEnvelope(args),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
  );
}
