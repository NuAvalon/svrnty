// src/lib/crypto/encrypted-backup.ts
// Argon2id-encrypted .svrnty file format
//
// The .svrnty file is the user's sovereign backup — it contains identity,
// keys, vault, and contacts. It MUST be encrypted with a user-chosen
// passphrase before saving to disk.
//
// Format: JSON envelope with Argon2id KDF parameters + AES-256-GCM ciphertext.
// The private key never exists in plaintext outside the browser.
//
// Spec reference: svrnty_unified_spec.md §Phase 1 — Flint finding #2.
// Parameters: Argon2id t=3, m=64MB (65536 KiB), p=1.

import { argon2id } from '@noble/hashes/argon2.js';
import type { SovereignBackup } from '@/lib/identity/client-store';

// ── Constants (Flint spec v0.1.3) ────────────────────────────────

const ARGON2_TIME_COST = 3;        // iterations
const ARGON2_MEMORY_COST = 65536;  // 64 MB in KiB
const ARGON2_PARALLELISM = 1;
const ARGON2_KEY_LENGTH = 32;      // 256-bit key for AES-256-GCM
const SALT_LENGTH = 16;            // 128-bit salt
const IV_LENGTH = 12;              // 96-bit IV for AES-GCM
const FORMAT_VERSION = '1.0';

// ── Types ────────────────────────────────────────────────────────

/** The encrypted .svrnty file format */
export interface EncryptedSvrntyFile {
  /** Format identifier */
  format: 'svrnty-encrypted';
  /** Format version */
  version: typeof FORMAT_VERSION;
  /** KDF parameters (stored so future versions can upgrade) */
  kdf: {
    algorithm: 'argon2id';
    salt: string;      // base64
    time_cost: number;
    memory_cost: number; // KiB
    parallelism: number;
  };
  /** AES-256-GCM encrypted payload */
  encrypted: {
    iv: string;         // base64
    ciphertext: string; // base64 (includes GCM auth tag)
  };
}

// ── Helpers ──────────────────────────────────────────────────────

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ── Core ─────────────────────────────────────────────────────────

/**
 * Derive an AES-256 key from a user passphrase using Argon2id.
 */
function deriveKey(passphrase: string, salt: Uint8Array): Uint8Array {
  const passphraseBytes = new TextEncoder().encode(passphrase);
  return argon2id(passphraseBytes, salt, {
    t: ARGON2_TIME_COST,
    m: ARGON2_MEMORY_COST,
    p: ARGON2_PARALLELISM,
    dkLen: ARGON2_KEY_LENGTH,
  });
}

/**
 * Encrypt a SovereignBackup into a .svrnty file.
 *
 * @param backup - The full sovereign backup (identity + keys + contacts)
 * @param passphrase - User-chosen passphrase (minimum 8 characters recommended)
 * @returns EncryptedSvrntyFile ready to be JSON.stringify'd and saved
 */
export async function encryptBackup(
  backup: SovereignBackup,
  passphrase: string,
): Promise<EncryptedSvrntyFile> {
  if (!passphrase || passphrase.length < 1) {
    throw new Error('Passphrase is required to encrypt backup');
  }

  // Generate random salt and IV
  const salt = new Uint8Array(SALT_LENGTH);
  crypto.getRandomValues(salt);
  const iv = new Uint8Array(IV_LENGTH);
  crypto.getRandomValues(iv);

  // Derive AES key from passphrase via Argon2id
  const keyBytes = deriveKey(passphrase, salt);
  const aesKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
  );

  // Zero the raw key bytes
  keyBytes.fill(0);

  // Encrypt the backup JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(backup));
  const ciphertextWithTag = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext)
  );

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

  const salt = fromBase64(file.kdf.salt);
  const iv = fromBase64(file.encrypted.iv);
  const ciphertext = fromBase64(file.encrypted.ciphertext);

  // Derive key using stored parameters (forward-compatible with upgrades)
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const keyBytes = argon2id(passphraseBytes, salt, {
    t: file.kdf.time_cost,
    m: file.kdf.memory_cost,
    p: file.kdf.parallelism,
    dkLen: ARGON2_KEY_LENGTH,
  });

  const aesKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  );

  // Zero the raw key bytes
  keyBytes.fill(0);

  try {
    const decrypted = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch {
    throw new Error('Decryption failed — wrong passphrase or corrupted file');
  }
}

/**
 * Check if a parsed JSON object is an encrypted .svrnty file.
 */
export function isEncryptedSvrntyFile(obj: unknown): obj is EncryptedSvrntyFile {
  if (!obj || typeof obj !== 'object') return false;
  const file = obj as Record<string, unknown>;
  return file.format === 'svrnty-encrypted'
    && typeof file.version === 'string'
    && typeof file.kdf === 'object'
    && typeof file.encrypted === 'object';
}
