// src/lib/crypto/password-envelope.ts
// The JSON envelope the export dialogs use for a file protected by a password (the contacts export, the private-key export, and the older full backup).
//
//   WRITE: Argon2id only. Every export path calls sealWithPassword, so no new file is ever written with the weaker password method.
//   READ:  dispatched on the file's own `kdf` tag, never on a guess. "argon2id" is the current format. "PBKDF2-SHA256-100k" is the format the app wrote before;
//          it is still READ so a backup someone already holds does not become a dead file, but it is read-only: nothing here can produce it.
//          Any other tag (or none) is refused, because a file we cannot identify must not be tried against a derivation by luck.
//
// The legacy read has its own fixed iteration count (LEGACY_PBKDF2_ITERATIONS). A file cannot raise or lower it, so a crafted file can neither unlock faster than
// the old format always did nor make the page spend unbounded time; the Argon2id parameters from a file are checked against the same limits as every other
// Argon2id read (kdf.ts assertParamsWithinLimits) before anything is derived.

import {
  ARGON2_KEY_LENGTH,
  MIN_PASSPHRASE_LENGTH,
  assertPassphraseStrength,
  IV_LENGTH,
  SALT_LENGTH,
  aesGcmDecrypt,
  aesGcmEncrypt,
  assertParamsWithinLimits,
  defaultArgon2Params,
  fromBase64,
  randomBytes,
  toBase64,
} from './kdf';
import { deriveKeyArgon2idOffThread } from './kdf-offthread';

/**
 * The shortest password an export may be protected with. The same floor as every other password in the app (the vault passphrase, the recovery sheet): a key
 * file carries the WHOLE identity, so it is exactly as strong as this password, and a memory-hard derivation slows guessing but does not rescue a short one.
 * The dialogs read their checks and their copy from this one constant, so the number on the screen cannot differ from the number enforced.
 */
export const MIN_EXPORT_PASSWORD_LENGTH = MIN_PASSPHRASE_LENGTH;

export const ENVELOPE_ALGORITHM = 'AES-256-GCM';
export const ENVELOPE_KDF_ARGON2ID = 'argon2id';
/** The tag every older export wrote. Kept only to READ those files. */
export const ENVELOPE_KDF_LEGACY_PBKDF2 = 'PBKDF2-SHA256-100k';
/** A constant, on purpose: nothing in a file can change it. */
export const LEGACY_PBKDF2_ITERATIONS = 100_000;

export interface SealedEnvelope {
  algorithm: typeof ENVELOPE_ALGORITHM;
  kdf: typeof ENVELOPE_KDF_ARGON2ID;
  kdf_params: { time_cost: number; memory_cost: number; parallelism: number };
  salt: string;
  iv: string;
  data: string;
}

/** Refusals the dialogs can show as they are: a stable code and a sentence that names no secret and echoes nothing from the file. */
export class EnvelopeRefused extends Error {
  readonly code: 'not-an-envelope' | 'unknown-kdf' | 'unsafe-params' | 'bad-field';
  constructor(code: EnvelopeRefused['code'], message: string) { super(message); this.name = 'EnvelopeRefused'; this.code = code; }
}

/** What the Argon2id tag authenticates, besides the ciphertext: change the algorithm, the tag or any parameter and the decrypt fails. */
function aadFor(p: { time_cost: number; memory_cost: number; parallelism: number }): Uint8Array {
  return new TextEncoder().encode(`svrnty-password-envelope-v1|${ENVELOPE_ALGORITHM}|${ENVELOPE_KDF_ARGON2ID}|${p.time_cost}|${p.memory_cost}|${p.parallelism}`);
}

/** Encrypt `plaintext` under `password`. Argon2id (in a worker), a fresh salt and iv, the parameters authenticated. The only way this module writes. */
export async function sealWithPassword(plaintext: Uint8Array, password: string): Promise<SealedEnvelope> {
  assertPassphraseStrength(password); // the writer refuses a short password itself, whoever calls it (the dialogs check first, for a clear message)
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const kdf_params = (({ time_cost, memory_cost, parallelism }) => ({ time_cost, memory_cost, parallelism }))(defaultArgon2Params(salt));
  const key = await deriveKeyArgon2idOffThread(password, salt, kdf_params);
  try {
    const ct = await aesGcmEncrypt(key, iv, plaintext, aadFor(kdf_params));
    return { algorithm: ENVELOPE_ALGORITHM, kdf: ENVELOPE_KDF_ARGON2ID, kdf_params, salt: toBase64(salt), iv: toBase64(iv), data: toBase64(ct) };
  } finally {
    key.fill(0);
  }
}

export interface OpenedEnvelope {
  plaintext: Uint8Array;
  /** true when the file used the older password method: the caller tells the owner to export a new copy. */
  legacy: boolean;
}

function b64Field(env: Record<string, unknown>, name: 'salt' | 'iv' | 'data'): Uint8Array {
  const v = env[name];
  if (typeof v !== 'string' || v.length === 0) throw new EnvelopeRefused('bad-field', `This file is missing its ${name}.`);
  try { return fromBase64(v); } catch { throw new EnvelopeRefused('bad-field', `This file's ${name} is not valid.`); }
}

/** Decrypt an envelope. Throws EnvelopeRefused for a file this version will not try, and lets a wrong password / damaged data surface as the platform's own decrypt failure. */
export async function openWithPassword(envelope: unknown, password: string): Promise<OpenedEnvelope> {
  if (envelope === null || typeof envelope !== 'object') throw new EnvelopeRefused('not-an-envelope', 'This is not a password-protected export.');
  const env = envelope as Record<string, unknown>;
  const salt = b64Field(env, 'salt');
  const iv = b64Field(env, 'iv');
  const data = b64Field(env, 'data');

  if (env.kdf === ENVELOPE_KDF_ARGON2ID) {
    const p = env.kdf_params as { time_cost?: unknown; memory_cost?: unknown; parallelism?: unknown } | undefined;
    if (!p || typeof p !== 'object') throw new EnvelopeRefused('unsafe-params', 'This file does not carry the settings it needs.');
    const params = { time_cost: p.time_cost as number, memory_cost: p.memory_cost as number, parallelism: p.parallelism as number };
    try { assertParamsWithinLimits({ algorithm: ENVELOPE_KDF_ARGON2ID, ...params }); }
    catch { throw new EnvelopeRefused('unsafe-params', 'This file asks for settings this version will not run.'); }
    if (salt.length !== SALT_LENGTH || iv.length !== IV_LENGTH) throw new EnvelopeRefused('bad-field', 'This file is not in a shape this version reads.');
    const key = await deriveKeyArgon2idOffThread(password, salt, params);
    try {
      return { plaintext: await aesGcmDecrypt(key, iv, data, aadFor(params)), legacy: false };
    } finally {
      key.fill(0);
    }
  }

  if (env.kdf === ENVELOPE_KDF_LEGACY_PBKDF2) {
    // READ-ONLY, and the iteration count is OURS: whatever the file says about iterations is not looked at.
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt as BufferSource, iterations: LEGACY_PBKDF2_ITERATIONS, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: ARGON2_KEY_LENGTH * 8 },
      false,
      ['decrypt'],
    );
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, data as BufferSource));
    return { plaintext: plain, legacy: true };
  }

  throw new EnvelopeRefused('unknown-kdf', 'This file uses a password method this version does not read.');
}

/**
 * The notice after an older-format restore. ONE constant, so the wording is reviewed once. The wording is the copy owner's (ledger row 169): "weaker" is true
 * and not alarming; it does not say the old file is broken or exposed; "keep that one instead" because the old file stays as weak as it was until replaced.
 * Forbidden in it: insecure / compromised / at risk / "we upgraded your file" / automatically.
 */
export const LEGACY_PASSWORD_METHOD_NOTICE =
  'This backup uses an older, weaker password method. It opened fine. Export a new copy now and keep that one instead, so your backup uses the current method.';
