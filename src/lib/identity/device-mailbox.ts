// src/lib/identity/device-mailbox.ts
/**
 * Device-mailbox lifecycle — the CARD-BORNE receiver-key layer for piece-2 emit/receive (the onion
 * EMIT-PATH deposit target). A device holds ONE long-lived random mailbox keypair, generated once at
 * identity genesis and vault-persisted (secrets never leave the device). Its PUBLIC keys + content-fp
 * ride INSIDE the signed identity card (envelope.ts IdentityCard.identity.mailbox_*), so a peer learns a
 * seal-target only from a MITM-proof signed card — NEVER from a relay-queryable identity→mailbox index
 * (the /mailbox/register direct-registry stays UNWIRED; Archie's blind-binding constitution gate).
 *
 * BOUNDARIES (Flint #159801 / Apollo #159806, Archie #159788):
 *   • The card carries a SEAL-TARGET (pubkeys + fp), NOT a deposit address. Per-pair deposit stays
 *     deriveRouteId(RouteRatchet(s_AB)) in the L2 onion transport — one mailbox keypair ≠ a deposit addr.
 *   • The device-mailbox keypair is DISTINCT from the identity key (receiver-only; one-device compromise
 *     reads only inbound mail, never the identity's ML-KEM decap core).
 *   • Mailbox pubkeys are a seal-target ⇒ as MITM-sensitive as pq_kem ⇒ stored from an imported card
 *     ONLY when that card's signature VERIFIED (classifyImportedCard branch 4). A no/invalid-signature
 *     card drops them → emit to that peer under-reveals (fail-closed), never seals to an attacker key.
 *
 * This module is PURE logic (no storage/session import — zero module cycle). The at-rest store
 * (vault-encrypted, fail-closed), the genesis/unlock lifecycle, and the owner-side receive accessor
 * getMyDeviceMailbox() all live in client-store.ts; this file holds the data-only helpers both the card
 * layer (import-validate) and the emit layer (peer seal-target) share.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { deriveMailboxFp, type MailboxPublicKeys } from '../crypto/mailbox-envelope.js';

const X25519_PK_HEX = 64;    // 32 bytes
const MLKEM1024_PK_HEX = 3136; // 1568 bytes
const FP_HEX = 64;           // SHA-256, 32 bytes

/**
 * The PUBLIC device-mailbox block. This is what rides on the signed card (card.identity.mailbox_*),
 * is cached on the owner's IdentityData wrapper (so the card builder can read it), and is stored on a
 * peer's ContactRecord.device_mailbox after a verified import. All hex. NO secret material.
 */
export interface DeviceMailboxPublic {
  mailbox_fp: string;            // 64 hex — content address = SHA256(x25519_pub ‖ mlkem1024_pub)
  mailbox_x25519_pk: string;     // 64 hex — 32B X25519 public
  mailbox_mlkem1024_pk: string;  // 3136 hex — 1568B ML-KEM-1024 encapsulation key
}

/** Is `s` a lowercase-hex string of exactly `len` chars? */
function isHex(s: unknown, len: number): s is string {
  return typeof s === 'string' && s.length === len && /^[0-9a-f]+$/.test(s);
}

/**
 * Validate a candidate public mailbox block: all three fields present, correct hex lengths, AND the
 * claimed mailbox_fp CONTENT-MATCHES its carried keys (fp = SHA256(x25519_pub ‖ mlkem1024_pub)). A block
 * that fails any check → null (fail-closed: drop → the peer/owner under-reveals, never seals to a
 * self-inconsistent target). Symmetric with the send-side fingerprintMatchesKey self-consistency guard.
 */
export function validateMailboxPublic(m: unknown): DeviceMailboxPublic | null {
  if (!m || typeof m !== 'object') return null;
  const o = m as Record<string, unknown>;
  if (!isHex(o.mailbox_fp, FP_HEX)) return null;
  if (!isHex(o.mailbox_x25519_pk, X25519_PK_HEX)) return null;
  if (!isHex(o.mailbox_mlkem1024_pk, MLKEM1024_PK_HEX)) return null;
  // Content-address self-consistency: recompute the fp from the carried keys and require an exact match.
  let derived: string;
  try {
    derived = deriveMailboxFp(hexToBytes(o.mailbox_x25519_pk), hexToBytes(o.mailbox_mlkem1024_pk));
  } catch {
    return null; // malformed bytes → drop
  }
  if (derived !== o.mailbox_fp) return null; // fp ≠ H(keys) → drop (self-inconsistent)
  return {
    mailbox_fp: o.mailbox_fp,
    mailbox_x25519_pk: o.mailbox_x25519_pk,
    mailbox_mlkem1024_pk: o.mailbox_mlkem1024_pk,
  };
}

/**
 * Extract a VALIDATED public mailbox block from a parsed card's `identity` sub-object, or null. The
 * CALLER (classifyImportedCard) MUST only trust the result when the card signature verified — this
 * helper does NOT check the signature (the mailbox fields live under identity.* so a valid card
 * signature already covers them; this is the shape/consistency gate on top). Absent fields → null
 * (legacy/pre-feature signer → emit under-reveals, fail-closed).
 */
export function extractValidMailboxFromCard(cardIdentity: unknown): DeviceMailboxPublic | null {
  if (!cardIdentity || typeof cardIdentity !== 'object') return null;
  const id = cardIdentity as Record<string, unknown>;
  // Absent entirely (legacy card) → null, quietly. Only validate when at least one field is present.
  if (id.mailbox_fp === undefined && id.mailbox_x25519_pk === undefined && id.mailbox_mlkem1024_pk === undefined) {
    return null;
  }
  return validateMailboxPublic({
    mailbox_fp: id.mailbox_fp,
    mailbox_x25519_pk: id.mailbox_x25519_pk,
    mailbox_mlkem1024_pk: id.mailbox_mlkem1024_pk,
  });
}

/**
 * A peer's device mailbox as a SEAL-TARGET, read from a stored ContactRecord. Returns the public keys
 * (as bytes, ready for sealToMailbox / sealForRoute) + the content fp, or null when the contact carries
 * no (or a malformed) mailbox — in which case emit to that peer under-reveals (fail-closed). Re-validates
 * the stored block (defense in depth; a stored record is trusted but cheap to re-check).
 */
export function peerDeviceMailbox(
  contact: { device_mailbox?: unknown } | null | undefined,
): { publicKeys: MailboxPublicKeys; fp: string } | null {
  const m = validateMailboxPublic(contact?.device_mailbox);
  if (!m) return null;
  return {
    publicKeys: {
      x25519Pub: hexToBytes(m.mailbox_x25519_pk),
      mlkem1024Pub: hexToBytes(m.mailbox_mlkem1024_pk),
    },
    fp: m.mailbox_fp,
  };
}

/** Build a public mailbox block (the stable hex shape for identity cache / card / contact) from keys. */
export function mailboxPublicOf(publicKeys: MailboxPublicKeys): DeviceMailboxPublic {
  return {
    mailbox_fp: deriveMailboxFp(publicKeys.x25519Pub, publicKeys.mlkem1024Pub),
    mailbox_x25519_pk: bytesToHex(publicKeys.x25519Pub),
    mailbox_mlkem1024_pk: bytesToHex(publicKeys.mlkem1024Pub),
  };
}
