// src/lib/sync/vault.ts
// Unified vault format — one encrypted file, everything inside.
// Like KeePass .kdbx but for sovereign identity + trust graph.
//
// ── .svrnty v3 (lane 0.10, 2026-08-16) ───────────────────────────────
// File format:
//   MAGIC (8 bytes): "SVRNTY\x00\x03"
//   HEADER_LEN (4 bytes): uint32 big-endian
//   HEADER (variable): JSON, cleartext — CRYPTO PARAMS ONLY (KeePass model):
//       { format, version:3, kdf:{argon2id salt+params}, iv }
//   BODY: AES-256-GCM ciphertext (+tag). AAD = MAGIC ‖ HEADER bytes.
//
// What changed from v2 and WHY:
//  • Body KDF is the SINGLE Argon2id path (crypto/kdf.ts), not the old
//    PBKDF2-600k in sync/backup.ts. One derivation to audit — "kill dual KDF".
//    Argon2id (t=3, m=64MB, p=1) is memory-hard and strictly stronger than the
//    retired PBKDF2-600k floor.
//  • The cleartext header is MINIMIZED to crypto params only. The old v2 header
//    leaked the owner's real name, fingerprint hint, contact count, device id,
//    and a plaintext "safe word" — all readable and FORGEABLE before any
//    passphrase. That data now lives in the ENCRYPTED body. A pre-passphrase
//    reader learns only "this is a svrnty v3 vault" (TYPE, not IDENTITY).
//  • The safe word is shown only AFTER a successful decrypt — where GCM has
//    authenticated it. Recognition ritual preserved; its timing fixed. A
//    cleartext safe word could be forged to phish "yes that's my vault"; an
//    authenticated one cannot.
//  • AAD binds MAGIC ‖ header (which carries version + kdf params + iv), so any
//    tamper — safe-word forge, version rollback, KDF downgrade, salt/iv swap —
//    fails decryption instead of being silently trusted.
//
// ── CLEAN-BREAK on v2 (Flint compat ruling #115328) ──────────────────
// We drop the v2 PBKDF2 read AND write entirely. This is safe ONLY because
// svrnty is PRE-LAUNCH:
//   • Vault export is local-download-only (no cloud upload is wired), so there
//     are no uninventoriable v2 files stored off-device.
//   • The 18 live identities run on the legacy Python relay — a different path,
//     NOT .svrnty vault files.
//   • The only possible holders of a v2 vault file are team/testers, whose
//     identities are LIVE in IndexedDB and therefore RE-EXPORTABLE under v3.
// So there is no irreversible-data-loss population, and keeping a v2 read path
// would just mean a PBKDF2 code path to audit forever. If a v2 file is ever
// presented we refuse it with an ACTIONABLE message (re-export from the live
// identity). If svrnty ever ships to real users who saved v2 backups, restore a
// QUARANTINED read-only v2 path keyed on the magic byte — never a v2 WRITE path.

import {
  type Argon2Params,
  defaultArgon2Params,
  deriveKeyArgon2id,
  aesGcmEncrypt,
  aesGcmDecrypt,
  assertParamsWithinLimits,
  assertPassphraseStrength,
  toBase64,
  fromBase64,
  randomBytes,
  SALT_LENGTH,
  IV_LENGTH,
} from '../crypto/kdf';
import type { TrustGraph } from '../trust/types';

// --- Magic bytes ---
const MAGIC_V3 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x03]); // "SVRNTY\0\3"
const MAGIC_V2 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x02]); // legacy, refused
const MAGIC_LEN = 8;
const HEADER_LEN_SIZE = 4;

// --- Types ---

/**
 * v3 cleartext header — crypto params ONLY. Everything identity-bearing lives in
 * the encrypted VaultContents and is authenticated by GCM before it is shown.
 */
export interface VaultHeader {
  format: 'svrnty-vault';
  version: 3;
  kdf: Argon2Params; // argon2id salt + params (needed to derive the key)
  iv: string; // base64 — AES-GCM IV (needed to decrypt)
}

export interface VaultContents {
  identity: VaultIdentity;
  keys: VaultKeys;
  trustGraph: TrustGraph;
  settings: VaultSettings;
  recovery: unknown | null; // KeyVault (Shamir shards metadata)
  sync: VaultSync;
}

export interface VaultIdentity {
  version: string;
  created_at: string;
  identity: {
    name: string;
    email: string;
    fingerprint: string;
    public_key: string;
  };
  verification: {
    status: 'unverified' | 'verified';
    method: string | null;
    verified_at: string | null;
    proof?: string;
  };
  metadata: {
    client_version: string;
    key_type: string;
    key_usage: string[];
  };
  post_quantum?: {
    sig_algorithm: 'ML-DSA-87';
    sig_public_key: string;
    kem_algorithm: 'ML-KEM-1024';
    kem_public_key: string;
  };
}

export interface VaultKeys {
  classical: {
    privateKey: string;
    passphrase: string;
  };
  pq: unknown | null; // serialized PQ keypair bundle
}

export interface VaultSettings {
  defaultDecayDays: number; // default: 730 (2 years)
  safeWord: string; // stored in the ENCRYPTED body; shown only after decrypt
  cloudSync?: {
    provider: 'local-file' | 'google-drive' | 'dropbox' | 'icloud' | 'webdav' | null;
    autoSync: boolean;
    lastSync: string | null;
    remoteFileId?: string; // provider-specific file ID
    webdavUrl?: string; // for WebDAV only
  };
}

export interface Tombstone {
  id: string; // ID of deleted entry
  deletedAt: string;
  deletedBy: string; // device ID
}

export interface MergeRecord {
  timestamp: string;
  deviceId: string;
  entriesAdded: number;
  entriesUpdated: number;
  entriesDeleted: number;
}

export interface VaultSync {
  deviceId: string;
  lastModified: string;
  tombstones: Tombstone[];
  mergeHistory: MergeRecord[];
}

// --- Vault Creation ---

/**
 * Generate a unique device ID for sync tracking.
 */
export function generateDeviceId(): string {
  const bytes = randomBytes(8);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Create a new vault from identity data.
 */
export function createVaultContents(
  identity: VaultIdentity,
  keys: VaultKeys,
  trustGraph: TrustGraph,
  settings: Partial<VaultSettings> = {},
  recovery: unknown | null = null,
): VaultContents {
  const deviceId = generateDeviceId();

  return {
    identity,
    keys,
    trustGraph,
    settings: {
      defaultDecayDays: settings.defaultDecayDays ?? 730,
      safeWord: settings.safeWord ?? '',
      cloudSync: settings.cloudSync ?? undefined,
    },
    recovery,
    sync: {
      deviceId,
      lastModified: new Date().toISOString(),
      tombstones: [],
      mergeHistory: [],
    },
  };
}

// --- Internal helpers ---

function magicMatches(bytes: Uint8Array, magic: Uint8Array): boolean {
  if (bytes.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) return false;
  }
  return true;
}

/** MAGIC_V3 ‖ headerBytes — the AAD that binds header (version + params) to the body. */
function buildAad(headerBytes: Uint8Array): Uint8Array {
  const aad = new Uint8Array(MAGIC_LEN + headerBytes.length);
  aad.set(MAGIC_V3, 0);
  aad.set(headerBytes, MAGIC_LEN);
  return aad;
}

/** Read the big-endian uint32 header length that follows the magic. */
function readHeaderLen(bytes: Uint8Array): number {
  return (
    ((bytes[MAGIC_LEN] << 24) |
      (bytes[MAGIC_LEN + 1] << 16) |
      (bytes[MAGIC_LEN + 2] << 8) |
      bytes[MAGIC_LEN + 3]) >>>
    0
  );
}

/**
 * Refuse a v2 (or unknown) file with an actionable message. See the CLEAN-BREAK
 * note at the top: pre-launch, the fix for a stranded v2 file is to re-export
 * from the live identity, not to keep a legacy PBKDF2 reader forever.
 */
function refuseLegacyOrUnknown(bytes: Uint8Array): never {
  if (magicMatches(bytes, MAGIC_V2)) {
    throw new Error(
      'This is a legacy v2 vault, no longer supported. Open your identity and ' +
        'export a fresh vault to upgrade it to the current format.',
    );
  }
  throw new Error('Not a valid .svrnty vault file');
}

// --- Vault Serialization ---

/**
 * Pack a vault into a .svrnty v3 file (ArrayBuffer).
 * Header = crypto params only (cleartext). Body = Argon2id + AES-256-GCM, with
 * the header bound as AAD.
 */
export async function packVault(contents: VaultContents, passphrase: string): Promise<ArrayBuffer> {
  assertPassphraseStrength(passphrase); // F3 — reject weak passphrases on write

  // Update lastModified
  contents.sync.lastModified = new Date().toISOString();

  // Fresh salt + IV per export (no nonce reuse).
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const kdf = defaultArgon2Params(salt);

  // Minimal cleartext header.
  const header: VaultHeader = {
    format: 'svrnty-vault',
    version: 3,
    kdf,
    iv: toBase64(iv),
  };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const aad = buildAad(headerBytes);

  // Derive + encrypt body (contents holds the identity, keys, safe word, etc.).
  const key = deriveKeyArgon2id(passphrase, salt, kdf);
  const bodyBytes = await aesGcmEncrypt(
    key,
    iv,
    new TextEncoder().encode(JSON.stringify(contents)),
    aad,
  );
  key.fill(0);

  // Pack: MAGIC(8) + HEADER_LEN(4) + HEADER(variable) + BODY(variable)
  const totalLen = MAGIC_LEN + HEADER_LEN_SIZE + headerBytes.length + bodyBytes.length;
  const result = new Uint8Array(totalLen);

  let offset = 0;
  result.set(MAGIC_V3, offset);
  offset += MAGIC_LEN;

  const headerLen = headerBytes.length;
  result[offset] = (headerLen >>> 24) & 0xff;
  result[offset + 1] = (headerLen >>> 16) & 0xff;
  result[offset + 2] = (headerLen >>> 8) & 0xff;
  result[offset + 3] = headerLen & 0xff;
  offset += HEADER_LEN_SIZE;

  result.set(headerBytes, offset);
  offset += headerBytes.length;

  result.set(bodyBytes, offset);

  return result.buffer;
}

/**
 * Read the cleartext header from a .svrnty v3 file WITHOUT the passphrase.
 * v3 headers carry only crypto params — there is nothing identity-bearing to
 * preview. Use this only to confirm "this is a svrnty vault" before prompting
 * for the passphrase. A v2/unknown file is refused with an actionable message.
 */
export function readVaultHeader(data: ArrayBuffer): VaultHeader {
  const bytes = new Uint8Array(data);

  if (!magicMatches(bytes, MAGIC_V3)) {
    refuseLegacyOrUnknown(bytes);
  }

  const headerLen = readHeaderLen(bytes);
  const headerStart = MAGIC_LEN + HEADER_LEN_SIZE;
  const headerBytes = bytes.slice(headerStart, headerStart + headerLen);
  const header = JSON.parse(new TextDecoder().decode(headerBytes));

  if (header.format !== 'svrnty-vault' || header.version !== 3) {
    throw new Error(`Unsupported vault format: ${header.format} v${header.version}`);
  }

  return header as VaultHeader;
}

/**
 * Decrypt and unpack a .svrnty v3 vault file.
 * Throws on a wrong passphrase, a corrupted file, or ANY tamper on the header
 * (the header is AAD-bound to the body).
 */
export async function unpackVault(
  data: ArrayBuffer,
  passphrase: string,
): Promise<{ header: VaultHeader; contents: VaultContents }> {
  const bytes = new Uint8Array(data);

  if (!magicMatches(bytes, MAGIC_V3)) {
    refuseLegacyOrUnknown(bytes);
  }

  const headerLen = readHeaderLen(bytes);
  const headerStart = MAGIC_LEN + HEADER_LEN_SIZE;
  const headerBytes = bytes.slice(headerStart, headerStart + headerLen);
  const header = JSON.parse(new TextDecoder().decode(headerBytes)) as VaultHeader;

  if (header.format !== 'svrnty-vault' || header.version !== 3) {
    throw new Error(`Unsupported vault format: ${header.format} v${header.version}`);
  }

  // F1: clamp/reject hostile KDF params BEFORE deriveKey — import is the
  // untrusted surface; a param-bomb would OOM/hang the browser on restore.
  assertParamsWithinLimits(header.kdf);

  const salt = fromBase64(header.kdf.salt);
  const iv = fromBase64(header.iv);
  const bodyBytes = bytes.slice(headerStart + headerLen);

  // AAD must be byte-identical to pack time: MAGIC ‖ the exact header bytes.
  const aad = buildAad(headerBytes);

  const key = deriveKeyArgon2id(passphrase, salt, header.kdf);
  try {
    const plaintext = await aesGcmDecrypt(key, iv, bodyBytes, aad);
    const contents = JSON.parse(new TextDecoder().decode(plaintext)) as VaultContents;
    return { header, contents };
  } catch {
    // Wrong passphrase, corrupted body, or tampered header. Never surface a
    // safe word here — there is nothing authenticated to show.
    throw new Error('Could not open vault — wrong passphrase or the file was altered');
  } finally {
    key.fill(0);
  }
}

// --- Vault Download (browser) ---

/**
 * Download a vault as a .svrnty file in the browser.
 */
export function downloadVault(data: ArrayBuffer, name?: string) {
  const filename = name || `vault-${new Date().toISOString().slice(0, 10)}.svrnty`;
  const blob = new Blob([data], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Read a vault file from a File input (browser).
 */
export async function readVaultFile(file: File): Promise<ArrayBuffer> {
  return file.arrayBuffer();
}
