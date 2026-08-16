// src/lib/crypto/encrypted-backup.ts
// Argon2id-encrypted .svrnty identity file format.
//
// The .svrnty identity file is the user's sovereign backup — it contains
// identity, keys, vault, and contacts. It MUST be encrypted with a user-chosen
// passphrase before saving to disk. The private key never exists in plaintext
// outside the browser.
//
// Format: JSON envelope with Argon2id KDF parameters + AES-256-GCM ciphertext.
//
// lane 0.10 (2026-08-16): the key derivation + AES-GCM now delegate to the
// SINGLE shared path in `crypto/kdf.ts` (kills the dual-KDF hazard — there is
// exactly one argon2id implementation in the tree now). The on-disk format and
// public API are UNCHANGED, so existing identity files still decrypt. Added F1
// hardening: the import path clamps KDF params (assertParamsWithinLimits)
// before deriveKey, so a crafted file can't OOM/hang the browser.
//
// Spec reference: svrnty_unified_spec.md §Phase 1 — Flint finding #2.
// Parameters: Argon2id t=3, m=64MB (65536 KiB), p=1  (Flint spec v0.1.3).

import type { SovereignBackup } from '@/lib/identity/client-store';
import {
  ARGON2_TIME_COST,
  ARGON2_MEMORY_COST,
  ARGON2_PARALLELISM,
  SALT_LENGTH,
  IV_LENGTH,
  toBase64,
  fromBase64,
  randomBytes,
  deriveKeyArgon2id,
  aesGcmEncrypt,
  aesGcmDecrypt,
  assertParamsWithinLimits,
} from './kdf';

const FORMAT_VERSION = '1.0';

// ── Types ────────────────────────────────────────────────────────────

/** The encrypted .svrnty file format */
export interface EncryptedSvrntyFile {
  /** Format identifier */
  format: 'svrnty-encrypted';
  /** Format version */
  version: typeof FORMAT_VERSION;
  /** KDF parameters (stored so future versions can upgrade) */
  kdf: {
    algorithm: 'argon2id';
    salt: string; // base64
    time_cost: number;
    memory_cost: number; // KiB
    parallelism: number;
  };
  /** AES-256-GCM encrypted payload */
  encrypted: {
    iv: string; // base64
    ciphertext: string; // base64 (includes GCM auth tag)
  };
}

// ── Core ─────────────────────────────────────────────────────────────

/**
 * Encrypt a SovereignBackup into a .svrnty file.
 *
 * @param backup - The full sovereign backup (identity + keys + contacts)
 * @param passphrase - User-chosen passphrase
 * @returns EncryptedSvrntyFile ready to be JSON.stringify'd and saved
 */
export async function encryptBackup(
  backup: SovereignBackup,
  passphrase: string,
): Promise<EncryptedSvrntyFile> {
  if (!passphrase || passphrase.length < 1) {
    throw new Error('Passphrase is required to encrypt backup');
  }

  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);

  // Derive AES key via the single shared Argon2id path.
  const keyBytes = deriveKeyArgon2id(passphrase, salt, {
    time_cost: ARGON2_TIME_COST,
    memory_cost: ARGON2_MEMORY_COST,
    parallelism: ARGON2_PARALLELISM,
  });

  const plaintext = new TextEncoder().encode(JSON.stringify(backup));
  const ciphertextWithTag = await aesGcmEncrypt(keyBytes, iv, plaintext);

  // Zero the raw key bytes
  keyBytes.fill(0);

  return {
    format: 'svrnty-encrypted',
    version: FORMAT_VERSION,
    kdf: {
      algorithm: 'argon2id',
      salt: toBase64(salt),
      time_cost: ARGON2_TIME_COST,
      memory_cost: ARGON2_MEMORY_COST,
      parallelism: ARGON2_PARALLELISM,
    },
    encrypted: {
      iv: toBase64(iv),
      ciphertext: toBase64(ciphertextWithTag),
    },
  };
}

/**
 * Decrypt a .svrnty file back into a SovereignBackup.
 *
 * @param file - The encrypted .svrnty file contents (parsed JSON)
 * @param passphrase - User's passphrase
 * @returns The decrypted SovereignBackup
 * @throws Error if passphrase is wrong or file is corrupted
 */
export async function decryptBackup(
  file: EncryptedSvrntyFile,
  passphrase: string,
): Promise<SovereignBackup> {
  if (file.format !== 'svrnty-encrypted') {
    throw new Error(`Unknown file format: ${file.format}`);
  }

  // F1: the file is untrusted — reject hostile KDF params BEFORE deriveKey,
  // so a param-bomb can't OOM/hang the browser on import.
  assertParamsWithinLimits(file.kdf);

  const salt = fromBase64(file.kdf.salt);
  const iv = fromBase64(file.encrypted.iv);
  const ciphertext = fromBase64(file.encrypted.ciphertext);

  const keyBytes = deriveKeyArgon2id(passphrase, salt, {
    time_cost: file.kdf.time_cost,
    memory_cost: file.kdf.memory_cost,
    parallelism: file.kdf.parallelism,
  });

  try {
    const decrypted = await aesGcmDecrypt(keyBytes, iv, ciphertext);
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch {
    throw new Error('Decryption failed — wrong passphrase or corrupted file');
  } finally {
    // Zero the raw key bytes whether or not decryption succeeded.
    keyBytes.fill(0);
  }
}

/**
 * Check if a parsed JSON object is an encrypted .svrnty file.
 */
export function isEncryptedSvrntyFile(obj: unknown): obj is EncryptedSvrntyFile {
  if (!obj || typeof obj !== 'object') return false;
  const file = obj as Record<string, unknown>;
  return (
    file.format === 'svrnty-encrypted' &&
    typeof file.version === 'string' &&
    typeof file.kdf === 'object' &&
    typeof file.encrypted === 'object'
  );
}
