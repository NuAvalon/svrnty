// src/lib/crypto/pq.ts
// Post-quantum cryptography wrapper using @noble/post-quantum
// ML-DSA-65 (FIPS 204) for signatures, ML-KEM-768 (FIPS 203) for key encapsulation

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// --- Types ---

export interface PQSigningKeypair {
  algorithm: 'ML-DSA-65';
  publicKey: Uint8Array;   // 1952 bytes
  secretKey: Uint8Array;   // 4032 bytes
}

export interface PQKEMKeypair {
  algorithm: 'ML-KEM-768';
  publicKey: Uint8Array;   // 1184 bytes
  secretKey: Uint8Array;   // 2400 bytes
}

export interface PQKeypairBundle {
  signing: PQSigningKeypair;
  kem: PQKEMKeypair;
}

export interface PQEncapsulationResult {
  ciphertext: Uint8Array;    // 1088 bytes
  sharedSecret: Uint8Array;  // 32 bytes
}

// --- Key Generation ---

export function generateSigningKeypair(): PQSigningKeypair {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  return { algorithm: 'ML-DSA-65', publicKey, secretKey };
}

export function generateKEMKeypair(): PQKEMKeypair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { algorithm: 'ML-KEM-768', publicKey, secretKey };
}

export function generatePQKeypairBundle(): PQKeypairBundle {
  return {
    signing: generateSigningKeypair(),
    kem: generateKEMKeypair(),
  };
}

// --- Signing ---

export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// --- Key Encapsulation ---

export function encapsulate(publicKey: Uint8Array): PQEncapsulationResult {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { ciphertext: cipherText, sharedSecret };
}

export function decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array
): Uint8Array {
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

// --- Serialization ---

export function publicKeyToBase64(key: Uint8Array): string {
  return Buffer.from(key).toString('base64');
}

export function base64ToPublicKey(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

export function serializeKeypairBundle(bundle: PQKeypairBundle): {
  signing: { algorithm: string; publicKey: string; secretKey: string };
  kem: { algorithm: string; publicKey: string; secretKey: string };
} {
  return {
    signing: {
      algorithm: bundle.signing.algorithm,
      publicKey: publicKeyToBase64(bundle.signing.publicKey),
      secretKey: Buffer.from(bundle.signing.secretKey).toString('base64'),
    },
    kem: {
      algorithm: bundle.kem.algorithm,
      publicKey: publicKeyToBase64(bundle.kem.publicKey),
      secretKey: Buffer.from(bundle.kem.secretKey).toString('base64'),
    },
  };
}

export function deserializeKeypairBundle(data: {
  signing: { algorithm: string; publicKey: string; secretKey: string };
  kem: { algorithm: string; publicKey: string; secretKey: string };
}): PQKeypairBundle {
  return {
    signing: {
      algorithm: 'ML-DSA-65',
      publicKey: base64ToPublicKey(data.signing.publicKey),
      secretKey: new Uint8Array(Buffer.from(data.signing.secretKey, 'base64')),
    },
    kem: {
      algorithm: 'ML-KEM-768',
      publicKey: base64ToPublicKey(data.kem.publicKey),
      secretKey: new Uint8Array(Buffer.from(data.kem.secretKey, 'base64')),
    },
  };
}
