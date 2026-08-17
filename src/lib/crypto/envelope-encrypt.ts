// src/lib/crypto/envelope-encrypt.ts
// Hybrid-envelope encryption — the "no non-hybrid ciphertext leaves the client" primitive.
// Implements svrnty_hybrid_envelope_format_v1 (Flint, s902; Peter #115657, Archie format-ACK #115682):
// ephemeral X25519 + ML-KEM key-encapsulation, HKDF-combined (BOTH-required), AES-256-GCM.
//
// This is NEW, ISOLATED code — it does not touch or change any existing path yet. The 5-site wiring
// (exchange.ts, contacts/db.ts + robust-db.ts, crypto-util.ts, trust/trust-graph.ts) and the Cat-3
// param alignment (pq.ts ML-KEM-1024/ML-DSA-87 → 768/65) are the deliberate follow-on. Deploy is
// hard-blocked; this is build.
//
// BOTH-REQUIRED BY CONSTRUCTION (format §3/§5, no OR-fallback): the AES key is
// deriveHybridSecret(s_classical, s_pq). Wrong or missing EITHER secret → a different key → GCM auth
// fails → decrypt throws. There is NO branch that decrypts with one secret (no acceptClassicalOnly
// analogue). The payload is AEAD-encrypted EXACTLY ONCE (aead_ct); epk_classical and kem_ct_pq are
// KEM shared-secret contributions, NEVER decryptable payload copies — this is the format-level kill of
// the redundant-classical-payload footgun.
//
// SUITE / DOWNGRADE-BINDING: HYBRID_SUITE_ID tracks pq.ts's params. pq.ts is currently ML-KEM-1024
// (Cat-5); the Cat-3 alignment retargets pq.ts and flips this constant to -cat3 with NO change to this
// file (it calls the pq.ts abstraction). On the wire, this envelope IS the `payload` of the 0.1 signed
// envelope, and suite_id is a signed field of that envelope (Archie nesting, #115682) — so the suite is
// integrity- and downgrade-bound by the existing 0.1 signature; no new signed surface here.

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { encapsulate as pqEncapsulate, decapsulate as pqDecapsulate, uint8ToBase64, base64ToUint8 } from './pq';
import { deriveHybridSecret } from './hybrid';

/** Reflects pq.ts's current KEM/DSA level. Cat-3 alignment retargets pq.ts and flips this to -cat3. */
export const HYBRID_SUITE_ID = 'svrnty-hybrid-v1-cat5';

/** The on-wire / at-rest hybrid ciphertext. The payload lives ONLY in aead_ct. */
export interface HybridEnvelope {
  suite_id: string;
  /** sender ephemeral X25519 public key (base64) — classical KEM contribution, not a payload copy */
  epk_classical: string;
  /** ML-KEM encapsulation ciphertext (base64) — PQ KEM contribution, not a payload copy */
  kem_ct_pq: string;
  /** AES-256-GCM nonce, 12 bytes (base64) */
  aead_iv: string;
  /** AES-256-GCM(payload) including the 16-byte tag (base64) — the SINGLE payload ciphertext */
  aead_ct: string;
}

export interface RecipientPublicKeys {
  /** Recipient Ed25519 public key (32 bytes); its Montgomery form is the X25519 DH target. */
  classicalEd25519PublicKey: Uint8Array;
  /** Recipient ML-KEM public key. */
  kemPublicKey: Uint8Array;
}

export interface RecipientSecretKeys {
  /** Recipient Ed25519 secret seed (32 bytes); Montgomery form is the X25519 DH scalar. */
  classicalEd25519SecretKey: Uint8Array;
  /** Recipient ML-KEM secret key. */
  kemSecretKey: Uint8Array;
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt `payload` to a recipient as a HybridEnvelope. Needs the recipient's classical AND PQ public
 * keys; produces a single AEAD ciphertext under a key that requires BOTH shared secrets to derive.
 */
export async function hybridEncryptToRecipient(
  payload: Uint8Array,
  recipient: RecipientPublicKeys,
): Promise<HybridEnvelope> {
  // Classical leg: ephemeral X25519, DH against the recipient's (Montgomery) public key.
  const eskClassical = crypto.getRandomValues(new Uint8Array(32));
  const epkClassical = x25519.getPublicKey(eskClassical);
  const recipientX = ed25519.utils.toMontgomery(recipient.classicalEd25519PublicKey);
  const sClassical = x25519.getSharedSecret(eskClassical, recipientX);

  // PQ leg: ML-KEM encapsulate to the recipient's KEM key.
  const { ciphertext: kemCt, sharedSecret: sPq } = pqEncapsulate(recipient.kemPublicKey);

  // Both-required combine → AES-256 key. Missing either secret cannot reproduce this key.
  const hybridKey = deriveHybridSecret(sClassical, sPq);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aeadCt = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await importAesKey(hybridKey), payload),
  );

  return {
    suite_id: HYBRID_SUITE_ID,
    epk_classical: uint8ToBase64(epkClassical),
    kem_ct_pq: uint8ToBase64(kemCt),
    aead_iv: uint8ToBase64(iv),
    aead_ct: uint8ToBase64(aeadCt),
  };
}

/**
 * Decrypt a HybridEnvelope. Recovers BOTH shared secrets and re-derives the key; if EITHER is
 * wrong/absent the GCM tag fails and this throws. No single-secret decrypt path exists.
 */
export async function hybridDecrypt(env: HybridEnvelope, me: RecipientSecretKeys): Promise<Uint8Array> {
  const myX = ed25519.utils.toMontgomerySecret(me.classicalEd25519SecretKey);
  const sClassical = x25519.getSharedSecret(myX, base64ToUint8(env.epk_classical));
  const sPq = pqDecapsulate(base64ToUint8(env.kem_ct_pq), me.kemSecretKey);

  const hybridKey = deriveHybridSecret(sClassical, sPq);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToUint8(env.aead_iv) },
    await importAesKey(hybridKey),
    base64ToUint8(env.aead_ct),
  );
  return new Uint8Array(pt);
}
