// src/lib/crypto/recovery.ts
// Key recovery via M-of-N Shamir Secret Sharing
// Master secret encrypts the private key vault; shards go to L3+ contacts
//
// Recovery paths:
//   1. M-of-N shards from trusted contacts -> reconstruct master secret -> decrypt vault
//   2. 24-word seed phrase (BIP39-style) -> master secret -> decrypt vault

import { split, combine } from 'shamir-secret-sharing';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

// --- Types ---

export interface KeyVault {
  version: '1.0.0';
  /** AES-256-GCM encrypted bundle of all private keys */
  encrypted_keys: string;  // base64
  /** GCM auth tag */
  auth_tag: string;        // base64
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
  /** ML-DSA-65 secret key, base64 */
  pq_signing_secret_key: string;
  /** ML-KEM-768 secret key, base64 */
  pq_kem_secret_key: string;
}

// --- Master Secret ---

/**
 * Generate a cryptographically random 32-byte master secret.
 */
export function generateMasterSecret(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

/**
 * Hash the master secret for verification purposes.
 * Used to confirm correct reconstruction without exposing the secret.
 */
export function hashMasterSecret(secret: Uint8Array): string {
  return Buffer.from(sha256(secret)).toString('hex');
}

// --- Vault Encryption ---

/**
 * Encrypt a private key bundle with the master secret.
 * Uses AES-256-GCM for authenticated encryption.
 */
export function encryptVault(
  bundle: PrivateKeyBundle,
  masterSecret: Uint8Array
): Omit<KeyVault, 'shamir'> {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterSecret, iv);

  const plaintext = JSON.stringify(bundle);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    version: '1.0.0',
    encrypted_keys: encrypted.toString('base64'),
    auth_tag: authTag.toString('base64'),
    iv: iv.toString('base64'),
    master_secret_hash: hashMasterSecret(masterSecret),
  };
}

/**
 * Decrypt a private key bundle from the vault using the master secret.
 */
export function decryptVault(
  vault: KeyVault | Omit<KeyVault, 'shamir'>,
  masterSecret: Uint8Array
): PrivateKeyBundle {
  // Verify master secret hash
  const hash = hashMasterSecret(masterSecret);
  if (hash !== vault.master_secret_hash) {
    throw new Error('Invalid master secret — hash mismatch');
  }

  const iv = Buffer.from(vault.iv, 'base64');
  const authTag = Buffer.from(vault.auth_tag, 'base64');
  const encrypted = Buffer.from(vault.encrypted_keys, 'base64');

  const decipher = createDecipheriv('aes-256-gcm', masterSecret, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString('utf8'));
}

// --- Shamir Secret Sharing ---

/**
 * Split the master secret into N shards, requiring M to reconstruct.
 *
 * @param masterSecret - 32-byte master secret
 * @param threshold - minimum shards needed (M), must be >= 2
 * @param totalShares - total shards created (N), must be >= threshold
 * @param identityFingerprint - fingerprint for shard identification
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
    data: Buffer.from(data).toString('base64'),
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

  const rawShards = shards.map(s =>
    new Uint8Array(Buffer.from(s.data, 'base64'))
  );

  return combine(rawShards);
}

// --- Seed Phrase (BIP39-style) ---

// Simplified wordlist — in production, use the full BIP39 2048-word list.
// For now, we encode as hex words (each byte = 2 hex chars) for determinism.
// TODO: Replace with proper BIP39 mnemonic encoding when ready for production.

/**
 * Encode a master secret as a human-readable seed phrase.
 * Uses hex encoding split into 8 groups of 8 chars (32 bytes = 64 hex chars).
 *
 * In production, this should use BIP39 mnemonics (24 words from 2048-word list).
 */
export function masterSecretToSeedPhrase(secret: Uint8Array): string {
  const hex = Buffer.from(secret).toString('hex');
  // Split into 8 groups of 8 hex chars for readability
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
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

// --- Full Flow ---

/**
 * Create a complete key vault with Shamir shards.
 * Call this during identity creation.
 *
 * Returns:
 *   - vault: encrypted key bundle (store locally)
 *   - shards: distribute to L3+ contacts
 *   - seedPhrase: human-readable backup (show once, user writes down)
 *   - masterSecret: EPHEMERAL — zero after use, do NOT store
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
  const encryptedVault = encryptVault(bundle, masterSecret);
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
export function recoverFromSeedPhrase(
  vault: KeyVault,
  seedPhrase: string
): PrivateKeyBundle {
  const masterSecret = seedPhraseToMasterSecret(seedPhrase);
  return decryptVault(vault, masterSecret);
}
