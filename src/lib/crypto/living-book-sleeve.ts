// src/lib/crypto/living-book-sleeve.ts
//
// ONE shared PQ-hybrid confidentiality sleeve for the FOUR living-book deposits (notes, contact-updates,
// joiner-responses, trust-affirms). It swaps the classical OpenPGP `encrypt()` on each deposit's wire for
// the EXISTING, co-verified hybrid mailbox envelope (X25519 + ML-KEM-1024 → HKDF-SHA256 → AES-256-GCM),
// so the ciphertext on the wire is post-quantum-hybrid — Harvest-Now-Decrypt-Later defense.
//
// CONFIDENTIALITY-ONLY. The sleeve wraps bytes that are ALREADY SIGNED by each deposit's own sign-before-
// seal step; it adds NO signature and reads NO sender-auth. Each caller signs, then hands the signed wire
// bytes here exactly where `encrypt()` used to be.
//
// NO NEW CRYPTO — reuses live primitives only:
//   • sealToMailbox / openMailboxEnvelope .... crypto/mailbox-envelope.ts (Flint Track-A, reject-classical
//                                              by construction — a downgraded/absent PQ leg fails the GCM tag)
//   • armor/dearmor package string ........... crypto/contact-message.ts (one canonical wire shape)
//   • x25519 enc pub from the armored key .... identity/fingerprint.ts (same getEncryptionKey+0x40-strip
//                                              path contact-message.ts uses)
//   • ML-KEM-1024 pub from base64 ............ crypto/pq.ts
//
// The seal derives the recipient's mailbox identity INTERNALLY (sealToMailbox → deriveMailboxFp over the
// recipient's x25519+kem pubs); the open requires MY mailbox secrets + MY mailbox fp.

import {
  sealToMailbox,
  openMailboxEnvelope,
  type MailboxSecretKeys,
} from './mailbox-envelope';
import { asMailboxEnvelopePackage } from '@/lib/sync/hybrid-dual-read';
import { base64ToUint8 } from './pq';
import { encPubFromArmoredPublicKey, KEM_PUB_LEN } from '../identity/fingerprint';

/** MY mailbox open-material: the receiver secrets + the 64-hex mailbox fp a sender sealed to. */
export interface LivingBookHybridSecrets {
  secrets: MailboxSecretKeys; // { x25519Sec(32), mlkem1024Sec(3168) }
  myFp: string; // deriveMailboxFp(myX25519Pub, myMlkem1024Pub) — the recipient the sender sealed to
}

/**
 * SEAL already-signed wire bytes to a recipient, PQ-hybrid. The X25519 leg is derived from the recipient's
 * armored OpenPGP public key; the ML-KEM-1024 leg is the recipient's `pq_kem_public_key` (base64). Returns
 * the armored MailboxEnvelopePackage string (same shape as contact-message.ts). Throws (fail-LOUD for the
 * sender, who controls its own inputs) on an unreadable armored key or a wrong-length ML-KEM pubkey — the
 * per-recipient fail-CLOSED skip (no-pq-kem) is the SEND-SITE's job, before it ever calls this.
 */
export async function sealLivingBookHybrid(
  plaintextBytes: Uint8Array,
  recipientArmoredPub: string,
  recipientPqKemB64: string,
): Promise<string> {
  const x25519Pub = await encPubFromArmoredPublicKey(recipientArmoredPub);
  const mlkem1024Pub = base64ToUint8(recipientPqKemB64);
  if (mlkem1024Pub.length !== KEM_PUB_LEN) {
    throw new Error(`sealLivingBookHybrid: recipient ML-KEM pub must be ${KEM_PUB_LEN}B, got ${mlkem1024Pub.length}`);
  }
  const pkg = await sealToMailbox(plaintextBytes, { x25519Pub, mlkem1024Pub });
  // RAW JSON on the wire (NOT armored): the consume dual-read discriminator (hybrid-dual-read.ts
  // asMailboxEnvelopePackage) is JSON.parse — a hybrid blob is the {v:1,epk,kem_ct,nonce,ct} JSON,
  // a classical blob is armored PGP. Armoring here would make every hybrid blob read as "classical"
  // → fall through → silent-loss. One canonical format; one discriminator. (Flint seam-fix 2026-10-10.)
  return JSON.stringify(pkg);
}

/**
 * OPEN an armored living-book blob with MY mailbox secrets. Returns the plaintext bytes, or null when the
 * blob is NOT a hybrid MailboxEnvelopePackage (e.g. a classical OpenPGP/armored string) — the signal each
 * per-type opener uses to FALL THROUGH to its classical decryptor (dual-read). Also null on wrong-recipient
 * / tamper / downgraded PQ leg (openMailboxEnvelope's reject-classical path). NEVER throws on hostile input.
 */
export async function openLivingBookHybrid(
  blob: string,
  mySecrets: MailboxSecretKeys,
  myFp: string,
): Promise<Uint8Array | null> {
  const pkg = asMailboxEnvelopePackage(blob); // ONE discriminator (JSON.parse): raw-JSON pkg vs armored-PGP classical
  if (!pkg) return null; // not a hybrid package → caller falls back to the classical decryptor
  return openMailboxEnvelope(pkg, mySecrets, myFp);
}
