// src/lib/crypto/recovery.ts
// Key recovery via M-of-N Shamir Secret Sharing
// Master secret encrypts the private key vault; shards go to L3+ contacts
//
// Recovery paths:
//   1. M-of-N shards from trusted contacts -> reconstruct master secret -> decrypt vault
//   2. 24-word seed phrase (BIP39-style) -> master secret -> decrypt vault
//
// Browser-compatible: uses Web Crypto API (no Node.js crypto/Buffer)

import { split, combine } from 'shamir-secret-sharing';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// --- Helpers (replace Node.js Buffer) ---

function toBase64(bytes: Uint8Array): string {
  // Loop, NOT String.fromCharCode(...bytes): spreading a large byte array exceeds the argument-count
  // limit on mobile browsers ("too many function arguments"). Same safe pattern kdf.ts / pq.ts use.
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// --- Types ---

export interface KeyVault {
  version: '1.0.0';
  /** AES-256-GCM encrypted bundle of all private keys */
  encrypted_keys: string;  // base64
  /** GCM auth tag */
  auth_tag: string;        // base64 (unused in WebCrypto — tag appended to ciphertext)
  /** Initialization vector */
  iv: string;              // base64
  /** Shamir parameters */
  shamir: {
    threshold: number;     // M (minimum shards needed)
    total_shares: number;  // N (total shards created)
  };
  /** Hash of master secret for verification (SHA-256, not reversible) */
  master_secret_hash: string;  // hex
}

export interface Shard {
  /** Shard index (for identification, not security) */
  index: number;
  /** The actual shard data, base64-encoded */
  data: string;
  /** Fingerprint of the identity this shard belongs to */
  identity_fingerprint: string;
  /** Threshold needed to reconstruct */
  threshold: number;
}

export interface PrivateKeyBundle {
  /** PGP armored private key (ED25519) */
  classical_private_key: string;
  /** Passphrase for PGP key */
  classical_passphrase: string;
  /** ML-DSA-87 secret key, base64 */
  pq_signing_secret_key: string;
  /** ML-KEM-1024 secret key, base64 */
  pq_kem_secret_key: string;
}

// --- Master Secret ---

/**
 * Generate a cryptographically random 32-byte master secret.
 */
export function generateMasterSecret(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Hash the master secret for verification purposes.
 * Used to confirm correct reconstruction without exposing the secret.
 */
export function hashMasterSecret(secret: Uint8Array): string {
  return bytesToHex(sha256(secret));
}

// --- Vault Encryption (Web Crypto API) ---

/**
 * Encrypt a private key bundle with the master secret.
 * Uses AES-256-GCM for authenticated encryption.
 */
export async function encryptVault(
  bundle: PrivateKeyBundle,
  masterSecret: Uint8Array
): Promise<Omit<KeyVault, 'shamir'>> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const key = await crypto.subtle.importKey(
    'raw', masterSecret, { name: 'AES-GCM' }, false, ['encrypt']
  );

  const plaintext = new TextEncoder().encode(JSON.stringify(bundle));
  const ciphertextWithTag = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  );

  // WebCrypto appends the 16-byte auth tag to the ciphertext
  const encrypted = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);
  const authTag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);

  return {
    version: '1.0.0',
    encrypted_keys: toBase64(encrypted),
    auth_tag: toBase64(authTag),
    iv: toBase64(iv),
    master_secret_hash: hashMasterSecret(masterSecret),
  };
}

/**
 * Decrypt a private key bundle from the vault using the master secret.
 */
export async function decryptVault(
  vault: KeyVault | Omit<KeyVault, 'shamir'>,
  masterSecret: Uint8Array
): Promise<PrivateKeyBundle> {
  // Verify master secret hash
  const hash = hashMasterSecret(masterSecret);
  if (hash !== vault.master_secret_hash) {
    throw new Error('Invalid master secret — hash mismatch');
  }

  const iv = fromBase64(vault.iv);
  const authTag = fromBase64(vault.auth_tag);
  const encrypted = fromBase64(vault.encrypted_keys);

  // WebCrypto expects ciphertext + tag concatenated
  const ciphertextWithTag = new Uint8Array(encrypted.length + authTag.length);
  ciphertextWithTag.set(encrypted);
  ciphertextWithTag.set(authTag, encrypted.length);

  const key = await crypto.subtle.importKey(
    'raw', masterSecret, { name: 'AES-GCM' }, false, ['decrypt']
  );

  const decrypted = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertextWithTag)
  );

  return JSON.parse(new TextDecoder().decode(decrypted));
}

// --- Shamir Secret Sharing ---

/**
 * Split the master secret into N shards, requiring M to reconstruct.
 */
export async function createShards(
  masterSecret: Uint8Array,
  threshold: number,
  totalShares: number,
  identityFingerprint: string
): Promise<Shard[]> {
  if (threshold < 2) throw new Error('Threshold must be at least 2');
  if (totalShares < threshold) throw new Error('Total shares must be >= threshold');
  if (totalShares > 255) throw new Error('Maximum 255 shares');

  const rawShards = await split(masterSecret, totalShares, threshold);

  return rawShards.map((data, i) => ({
    index: i + 1,
    data: toBase64(new Uint8Array(data)),
    identity_fingerprint: identityFingerprint,
    threshold,
  }));
}

/**
 * Reconstruct the master secret from M-of-N shards.
 */
export async function reconstructFromShards(
  shards: Shard[]
): Promise<Uint8Array> {
  if (shards.length < 2) {
    throw new Error('Need at least 2 shards to reconstruct');
  }

  const rawShards = shards.map(s => fromBase64(s.data));
  return combine(rawShards);
}

// --- Seed Phrase (BIP39-style) ---

/**
 * Encode a master secret as a human-readable seed phrase.
 * Uses hex encoding split into 8 groups of 8 chars (32 bytes = 64 hex chars).
 */
export function masterSecretToSeedPhrase(secret: Uint8Array): string {
  const hex = bytesToHex(secret);
  const groups: string[] = [];
  for (let i = 0; i < hex.length; i += 8) {
    groups.push(hex.slice(i, i + 8));
  }
  return groups.join(' ');
}

/**
 * Decode a seed phrase back to the master secret.
 */
export function seedPhraseToMasterSecret(phrase: string): Uint8Array {
  const hex = phrase.replace(/\s+/g, '');
  if (hex.length !== 64) {
    throw new Error('Invalid seed phrase — expected 64 hex characters (32 bytes)');
  }
  return hexToBytes(hex);
}

// --- Full Flow ---

/**
 * Create a complete key vault with Shamir shards.
 * Call this during identity creation.
 */
export async function createKeyVault(
  bundle: PrivateKeyBundle,
  threshold: number,
  totalShares: number,
  identityFingerprint: string
): Promise<{
  vault: KeyVault;
  shards: Shard[];
  seedPhrase: string;
  masterSecret: Uint8Array;
}> {
  const masterSecret = generateMasterSecret();
  const encryptedVault = await encryptVault(bundle, masterSecret);
  const shards = await createShards(masterSecret, threshold, totalShares, identityFingerprint);
  const seedPhrase = masterSecretToSeedPhrase(masterSecret);

  const vault: KeyVault = {
    ...encryptedVault,
    shamir: { threshold, total_shares: totalShares },
  };

  return { vault, shards, seedPhrase, masterSecret };
}

/**
 * Recover keys from Shamir shards.
 */
export async function recoverFromShards(
  vault: KeyVault,
  shards: Shard[]
): Promise<PrivateKeyBundle> {
  const masterSecret = await reconstructFromShards(shards);
  return decryptVault(vault, masterSecret);
}

/**
 * Recover keys from seed phrase.
 */
export async function recoverFromSeedPhrase(
  vault: KeyVault,
  seedPhrase: string
): Promise<PrivateKeyBundle> {
  const masterSecret = seedPhraseToMasterSecret(seedPhrase);
  return decryptVault(vault, masterSecret);
}
