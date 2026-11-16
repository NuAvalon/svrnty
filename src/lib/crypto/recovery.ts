// src/lib/crypto/recovery.ts
// Key recovery via M-of-N Shamir Secret Sharing
// Master secret encrypts the private key vault; shards go to L3+ contacts
//
// Recovery paths:
//   1. M-of-N shards from trusted contacts -> reconstruct master secret -> decrypt vault
//   2. 24-word seed phrase (BIP39-style) -> master secret -> decrypt vault
//
// Browser-compatible: uses Web Crypto API (no Node.js crypto/Buffer)

import { RestoreThrow } from './coded-error';
import { newSetId, commitSet, sortPieces, parseCommitments, type PieceCommitments, type BadPieceReason } from './recovery-commit';
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
    /** A commitment to each piece (recovery-commit.ts), in the backup's readable outer so a person who lost the device still has it. Absent in older vaults.
     *  It can only MISCLASSIFY pieces: master_secret_hash below stays the final authority on whether a rebuilt secret is the right one. */
    pieces?: PieceCommitments;
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
  /** ML-DSA-87 PUBLIC key, base64 — carried so RESTORE can reconstruct the canonical fp
   *  SHA256(sign‖enc‖kem‖sig) without deriving pub-from-secret (@noble exposes no ML-DSA
   *  secret→public; ML-DSA's pub is not a substring of its secret). Optional for back-compat:
   *  pre-fix seed vaults lack it → restore fails gracefully (see recovery-canonical fix). */
  pq_signing_public_key?: string;
  /** ML-KEM-1024 PUBLIC key, base64 — carried for canonical-fp reconstruction on restore. */
  pq_kem_public_key?: string;
  /** Canonical identity fingerprint (SHA256 of the 4 pubs). Carried so SEED restore has a claim to
   *  check its recompute against. Lives INSIDE this AES-GCM-encrypted bundle (never the plaintext
   *  KeyVault outer) so the recovery envelope stays identity-blind. Optional: pre-fix seed vaults
   *  lack it -> seed restore fails closed (acceptable; those are pre-9/9). */
  identity_fingerprint?: string;
  /** #532 C1: the identity's DURABLE key epoch when this bundle was sealed (genesis = 0). Absent = 0: every bundle sealed before
   *  this field is a genesis bundle. Inside the AES-GCM bundle, so authenticated. Read by restore-durable.ts. */
  durable_epoch?: number;
  /** #532 C1: the DURABLE id (the genesis fingerprint, unchanged across rotations; identity_fingerprint is the CURRENT one).
   *  Required by restore when durable_epoch > 0. */
  durable_fingerprint?: string;
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
    throw new RestoreThrow('recovery-code-wrong', 'Invalid master secret — hash mismatch');
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
    throw new RestoreThrow('recovery-code-malformed', 'Invalid seed phrase — expected 64 hex characters (32 bytes)');
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
    shamir: { threshold, total_shares: totalShares, pieces: commitSet(newSetId(), shards) },
  };

  return { vault, shards, seedPhrase, masterSecret };
}

/** Most M-subsets of the handed pieces that recovery will try when one of them is bad and the backup has no list to say which. Past it, recovery refuses. */
export const MAX_SUBSET_SEARCH = 1000;

/**
 * Recovery refused to rebuild from these pieces. The error carries only a code and a literal sentence, so nothing derived from the pieces can reach it; a screen that
 * wants to say WHICH pieces do not fit asks checkPieces.
 */
export class RecoveryPiecesRefused extends RestoreThrow {
  constructor(code: 'recovery-pieces-insufficient' | 'recovery-pieces-search-too-large', message: string) {
    super(code, message);
    this.name = 'RecoveryPiecesRefused';
  }
}

/** A piece the vault's list does not accept, by label and reason only: never piece data, a commitment value or the set id. */
export interface NamedBadPiece { index: number | null; reason: BadPieceReason }

/**
 * The pieces split by the vault's list: those that fit, and each that does not, named by label and reason. `listed` is false when the vault has no readable list
 * (an older backup, or one whose list does not parse): then nothing can be named and every piece is returned as `good` for the hash-based search to decide.
 * This is what a recovery screen asks to say which pieces to look at again; recoverFromShards uses the same split.
 */
export function checkPieces(vault: KeyVault, shards: Shard[]): { listed: boolean; good: Shard[]; bad: NamedBadPiece[] } {
  const rawList = vault.shamir?.pieces;
  const list = rawList === undefined ? null : parseCommitments(rawList);
  if (!list) return { listed: false, good: shards.slice(), bad: [] };
  const sorted = sortPieces(list, shards);
  return { listed: true, good: sorted.good, bad: sorted.bad.map((b) => ({ index: typeof b.index === 'number' ? b.index : null, reason: b.reason })) };
}

/** The vault's threshold if it is a plausible one. The outer comes from a file, so it is checked before it decides anything. */
function readThreshold(vault: KeyVault): number | null {
  const t = vault.shamir?.threshold;
  return typeof t === 'number' && Number.isInteger(t) && t >= 2 && t <= 255 ? t : null;
}

/** True when C(n, k) is larger than `cap`. Stops as soon as it is, so a huge n cannot make this slow. */
function binomialExceeds(n: number, k: number, cap: number): boolean {
  let c = 1;
  for (let i = 1; i <= k; i++) {
    c = (c * (n - k + i)) / i;
    if (c > cap) return true;
  }
  return false;
}

function* combinations(n: number, k: number): Generator<number[]> {
  const idx = Array.from({ length: k }, (_, i) => i);
  while (true) {
    yield [...idx];
    let i = k - 1;
    while (i >= 0 && idx[i] === n - k + i) i--;
    if (i < 0) return;
    idx[i]++;
    for (let j = i + 1; j < k; j++) idx[j] = idx[j - 1] + 1;
  }
}

/**
 * The secret that the vault's own hash accepts, from the pieces handed in, or null. Tries everything handed in together first; if that fails and there are more
 * pieces than the threshold, tries each threshold-sized subset (refusing, not cutting short, when there are more than MAX_SUBSET_SEARCH of them).
 * The hash is the only authority here: nothing in the vault's list or threshold can make a wrong secret pass.
 */
async function secretByHash(vault: KeyVault, shards: Shard[], threshold: number | null): Promise<Uint8Array | null> {
  const seen = new Set<string>();
  const uniq = shards.filter((s) => typeof s?.data === 'string' && !seen.has(s.data) && seen.add(s.data));
  const accepts = (secret: Uint8Array) => hashMasterSecret(secret) === vault.master_secret_hash;
  if (uniq.length >= 2) {
    try { const s = await reconstructFromShards(uniq); if (accepts(s)) return s; } catch { /* a bad or clashing piece: fall through to the search */ }
  }
  if (threshold === null || uniq.length <= threshold) return null;
  if (binomialExceeds(uniq.length, threshold, MAX_SUBSET_SEARCH)) {
    throw new RecoveryPiecesRefused('recovery-pieces-search-too-large', 'Too many pieces with a bad one among them to try the combinations.');
  }
  let tries = 0;
  for (const pick of combinations(uniq.length, threshold)) {
    // A backstop independent of the size check above: never more than the cap, whatever the vault's threshold says, so no outer can make this loop run on.
    if (++tries > MAX_SUBSET_SEARCH) return null;
    try { const s = await reconstructFromShards(pick.map((i) => uniq[i])); if (accepts(s)) return s; } catch { /* clashing labels in this subset */ }
  }
  return null;
}

/**
 * Recover keys from Shamir shards. A backup that carries a list of piece commitments has the pieces checked against it BEFORE combining (checkPieces), so a bad,
 * relabelled, foreign or repeated piece is left out and can be named, and M+1 pieces with one bad still open it. A backup without one, or a list that
 * does not hold up, falls back to searching subsets by the vault hash. Either way the vault's own hash decides: a wrong bundle is never returned.
 */
export async function recoverFromShards(
  vault: KeyVault,
  shards: Shard[]
): Promise<PrivateKeyBundle> {
  const threshold = readThreshold(vault);
  const need = threshold ?? 2;
  const checked = checkPieces(vault, shards);
  if (checked.listed && checked.good.length >= need) {
    const secret = await reconstructFromShards(checked.good).catch(() => null);
    // The hash decides, not the list: if it does not match, the list marked a bad piece good, and the search below finds the real secret or refuses.
    if (secret !== null && hashMasterSecret(secret) === vault.master_secret_hash) return decryptVault(vault, secret);
  }
  const found = await secretByHash(vault, shards, threshold);
  if (found) return decryptVault(vault, found);
  const distinct = new Set(shards.filter((s) => typeof s?.data === 'string').map((s) => s.data)).size;
  if (checked.bad.length > 0 || distinct < need) {
    throw new RecoveryPiecesRefused('recovery-pieces-insufficient', 'Not enough pieces that fit this backup to rebuild the recovery key.');
  }
  throw new RestoreThrow('recovery-code-wrong', 'Invalid master secret — hash mismatch');
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
