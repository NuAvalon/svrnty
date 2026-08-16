// src/lib/crypto/hybrid.ts
// Hybrid classical + post-quantum cryptography
// ED25519 + ML-DSA-87 for signatures
// Curve25519 + ML-KEM-1024 for key encapsulation
//
// Security model: BOTH classical AND post-quantum must be broken to compromise.

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  sign as pqSign,
  verify as pqVerify,
  encapsulate as pqEncapsulate,
  decapsulate as pqDecapsulate,
  generatePQKeypairBundle,
  publicKeyToBase64,
  base64ToPublicKey,
  serializeKeypairBundle,
  deserializeKeypairBundle,
  uint8ToBase64,
  base64ToUint8,
  type PQKeypairBundle,
} from './pq';
import {
  createMessage,
  encrypt,
  decrypt,
  sign as pgpSign,
  verify as pgpVerify,
  readKey,
  readPrivateKey,
  readMessage,
  decryptKey,
} from 'openpgp';

// --- Types ---

export interface HybridSignature {
  /** PGP cleartext signature (ED25519) */
  classical: string;
  /** ML-DSA-87 signature, base64-encoded */
  post_quantum: string;
  /** Algorithm identifier */
  algorithm: 'ED25519+ML-DSA-87';
}

export interface HybridEncryptionResult {
  /** PGP-encrypted payload (Curve25519) */
  classical_ciphertext: string;
  /** ML-KEM-1024 ciphertext for hybrid secret, base64 */
  pq_kem_ciphertext: string;
  /** AES-256-GCM encrypted payload using hybrid-derived key, base64 */
  hybrid_ciphertext: string;
  /** Algorithm identifier */
  algorithm: 'Curve25519+ML-KEM-1024';
}

export interface HybridPublicKeys {
  /** PGP armored public key (ED25519/Curve25519) */
  classical_public_key: string;
  /** ML-DSA-87 signing public key, base64 */
  pq_sig_public_key: string;
  /** ML-KEM-1024 encapsulation public key, base64 */
  pq_kem_public_key: string;
}

export interface HybridPrivateKeys {
  /** PGP armored private key */
  classical_private_key: string;
  /** Passphrase for PGP private key */
  classical_passphrase: string;
  /** Serialized PQ keypair bundle */
  pq_bundle: ReturnType<typeof serializeKeypairBundle>;
}

// --- Key Generation ---

export interface HybridKeypairResult {
  publicKeys: HybridPublicKeys;
  privateKeys: HybridPrivateKeys;
}

/**
 * Generate a complete hybrid keypair bundle.
 * Called during identity creation — produces classical + PQ keys.
 *
 * @param classicalPrivateKey - PGP armored private key (from openpgp generateKey)
 * @param classicalPublicKey - PGP armored public key
 * @param classicalPassphrase - passphrase for the PGP key
 */
export function generateHybridKeys(
  classicalPrivateKey: string,
  classicalPublicKey: string,
  classicalPassphrase: string
): HybridKeypairResult {
  const pqBundle = generatePQKeypairBundle();

  return {
    publicKeys: {
      classical_public_key: classicalPublicKey,
      pq_sig_public_key: publicKeyToBase64(pqBundle.signing.publicKey),
      pq_kem_public_key: publicKeyToBase64(pqBundle.kem.publicKey),
    },
    privateKeys: {
      classical_private_key: classicalPrivateKey,
      classical_passphrase: classicalPassphrase,
      pq_bundle: serializeKeypairBundle(pqBundle),
    },
  };
}

// --- Hybrid Signing ---

/**
 * Create a hybrid dual signature over a payload.
 * Signs with ED25519 (PGP) AND ML-DSA-87.
 * Both must be broken to forge.
 */
export async function hybridSign(
  payload: string,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey: Uint8Array
): Promise<HybridSignature> {
  // 1. Classical ED25519 signature via openpgp
  const privateKeyObj = await readPrivateKey({ armoredKey: classicalPrivateKeyArmored });
  const decryptedKey = await decryptKey({
    privateKey: privateKeyObj,
    passphrase: classicalPassphrase,
  });

  const message = await createMessage({ text: payload });
  const classicalSig = await pgpSign({
    message,
    signingKeys: decryptedKey,
  });

  // 2. Post-quantum ML-DSA-87 signature
  const payloadBytes = new TextEncoder().encode(payload);
  const pqSig = pqSign(payloadBytes, pqSigningSecretKey);

  return {
    classical: classicalSig.toString(),
    post_quantum: uint8ToBase64(pqSig),
    algorithm: 'ED25519+ML-DSA-87',
  };
}

/**
 * Verify a hybrid dual signature.
 * BOTH signatures must verify for the payload to be accepted.
 *
 * @param acceptClassicalOnly - if true, accept v1 identities with no PQ sig.
 *   Default false (strict mode). Set true for backward compat with v1 peers.
 */
export async function hybridVerify(
  payload: string,
  signature: HybridSignature | { classical: string },
  classicalPublicKeyArmored: string,
  pqSigningPublicKey?: Uint8Array,
  acceptClassicalOnly: boolean = false
): Promise<boolean> {
  // 1. Verify the classical ED25519 signature AND that it signs EXACTLY `payload`.
  //    openpgp.sign() returns an INLINE signed message (the data is embedded in the armored blob).
  //    Verifying it alone proves "some validly-signed message" — NOT "signs the caller's payload".
  //    Without the literal check below, `payload` is UNBOUND on the classical path: an attacker
  //    re-wraps a validly-signed inner message under different outer fields and this still passes.
  //    The PQ branch already binds `payload`; binding it here too means every path discharges the
  //    obligation rather than relocating it to "future callers beware".
  let classicalValid = false;
  try {
    const signedMessage = await readMessage({
      armoredMessage: signature.classical,
    });
    const literal = signedMessage.getLiteralData();
    if (literal == null || new TextDecoder().decode(literal) !== payload) return false;
    const publicKey = await readKey({ armoredKey: classicalPublicKeyArmored });
    const verification = await pgpVerify({
      message: signedMessage,
      verificationKeys: publicKey,
    });
    classicalValid = await verification.signatures[0].verified;
  } catch {
    return false;
  }

  if (!classicalValid) return false;

  // 2. Check if this is a hybrid signature
  const isHybrid = 'post_quantum' in signature && 'algorithm' in signature;

  if (!isHybrid) {
    // Classical-only signature from a v1 identity
    return acceptClassicalOnly;
  }

  // 3. Verify post-quantum ML-DSA-87 signature
  if (!pqSigningPublicKey) {
    // We have a hybrid sig but no PQ public key — reject
    return false;
  }

  const hybridSig = signature as HybridSignature;
  const payloadBytes = new TextEncoder().encode(payload);
  const pqSigBytes = base64ToUint8(hybridSig.post_quantum);

  return pqVerify(payloadBytes, pqSigBytes, pqSigningPublicKey);
}

// --- Hybrid Key Encapsulation ---

const HYBRID_HKDF_INFO = new TextEncoder().encode('soverentity-hybrid-kem-v1');

/**
 * Derive a hybrid shared secret by combining classical and PQ shared secrets.
 * Uses HKDF-SHA256 to combine both into a single 32-byte key.
 */
export function deriveHybridSecret(
  classicalSecret: Uint8Array,
  pqSecret: Uint8Array
): Uint8Array {
  // Concatenate both secrets as IKM
  const combined = new Uint8Array(classicalSecret.length + pqSecret.length);
  combined.set(classicalSecret);
  combined.set(pqSecret, classicalSecret.length);

  // HKDF extract + expand to 32 bytes
  return hkdf(sha256, combined, undefined, HYBRID_HKDF_INFO, 32);
}

/**
 * Hybrid encapsulation: generates a PQ shared secret using ML-KEM-1024.
 * The caller combines this with the classical shared secret (from openpgp encrypt).
 *
 * Returns the KEM ciphertext and shared secret.
 */
export function hybridEncapsulate(pqKemPublicKey: Uint8Array): {
  ciphertext: string;
  sharedSecret: Uint8Array;
} {
  const { ciphertext, sharedSecret } = pqEncapsulate(pqKemPublicKey);
  return {
    ciphertext: uint8ToBase64(ciphertext),
    sharedSecret,
  };
}

/**
 * Hybrid decapsulation: recovers the PQ shared secret from ML-KEM-1024 ciphertext.
 * The caller combines this with the classical shared secret.
 */
export function hybridDecapsulate(
  ciphertextB64: string,
  pqKemSecretKey: Uint8Array
): Uint8Array {
  const ciphertext = base64ToUint8(ciphertextB64);
  return pqDecapsulate(ciphertext, pqKemSecretKey);
}

// --- Utility ---

/**
 * Check if an identity has post-quantum keys.
 */
export function isQuantumReady(identity: {
  post_quantum?: {
    sig_public_key?: string;
    kem_public_key?: string;
  };
}): boolean {
  return !!(
    identity.post_quantum?.sig_public_key &&
    identity.post_quantum?.kem_public_key
  );
}

// Re-export PQ utilities for convenience
export {
  publicKeyToBase64,
  base64ToPublicKey,
  serializeKeypairBundle,
  deserializeKeypairBundle,
} from './pq';
export type { PQKeypairBundle } from './pq';
