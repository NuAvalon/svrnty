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
//
// ── .svrnty v4 (recovery dual-envelope, 2026-08-29) ──────────────────
// File format:
//   MAGIC (8 bytes): "SVRNTY\x00\x04"
//   HEADER_LEN (4 bytes): uint32 big-endian
//   HEADER (variable): JSON, cleartext — CRYPTO PARAMS ONLY (as v3), version:4
//   BODY_LEN (4 bytes): uint32 big-endian — exact length of the passphrase body
//   BODY: AES-256-GCM(passphrase) of VaultContents. AAD = MAGIC ‖ HEADER.
//   RECOVERY (rest of file): the `recovery` KeyVault, already master-encrypted
//       (encryptVault = AES-256-GCM under the 32-byte master secret = the seed),
//       stored OUTSIDE the passphrase layer so it is extractable with NO
//       passphrase. Empty (0 bytes) when no recovery vault was configured.
//
// WHY v4 (the recovery-after-loss fix):
//  • v3 buried the recovery KeyVault INSIDE the passphrase body. Reaching it
//    required the passphrase — so "lost passphrase → recover with seed/guardians"
//    was architecturally IMPOSSIBLE (you could never get to the KeyVault). A
//    "recover without your passphrase" button on v3 would be a FALSE PROMISE.
//  • v4 carries the SAME KeyVault a second time, master-encrypted, OUTSIDE the
//    passphrase layer. extractRecoveryVault(data) reads it with no passphrase;
//    recoverFromSeedPhrase / recoverFromShards then reconstruct the identity.
//  • SAFE: the recovery envelope is AES-256-GCM under a 32-byte CSPRNG master
//    secret (= the seed). An attacker with the .svrnty still cannot open it
//    without the seed, and a seed-holder ALREADY controls the identity — so
//    "openable by seed, no passphrase" grants an attacker-with-the-seed nothing
//    new. The passphrase double-lock on the recovery vault was redundant, not
//    load-bearing. Daily unlock is unchanged (passphrase + AAD-bound GCM).
//  • The recovery envelope, like the v3 header, reveals TYPE not IDENTITY: it is
//    ciphertext + iv + tag + a SHA-256 of a full-entropy secret + the M-of-N
//    counts. No name / fingerprint / safe-word. (Residual: master_secret_hash is
//    stable, so two backups of the SAME identity are linkable to each other — a
//    minor metadata leak, not a deanonymization; accepted vs. the far greater
//    harm of an unrecoverable identity. master_secret_hash cannot be stripped —
//    decryptVault needs it to reject a wrong reconstruction. Flagged for follow-up.)
//  • The daily BODY is now length-prefixed (BODY_LEN) so the recovery envelope
//    can follow it. Tampering BODY_LEN fails CLOSED: the daily path fails the GCM
//    tag, the recovery path fails master_secret_hash — neither loads a wrong key.
//
// ── MIGRATION v3 → v4 ────────────────────────────────────────────────
// unpackVault still READS v3 (passphrase daily unlock) so existing backups open.
// packVault now WRITES v4 on every export. A v3 file has NO recovery envelope, so
// extractRecoveryVault refuses it with an actionable "re-export to enable seed
// recovery" message. Users must re-export once to gain passphrase-free recovery.

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
import type { KeyVault, GraphVault } from '../crypto/recovery';

// --- Magic bytes ---
const MAGIC_V4 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x04]); // "SVRNTY\0\4"
const MAGIC_V3 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x03]); // "SVRNTY\0\3", read-only (migration)
const MAGIC_V2 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x02]); // legacy, refused
const MAGIC_LEN = 8;
const HEADER_LEN_SIZE = 4;
const BODY_LEN_SIZE = 4; // v4: uint32 BE length of the passphrase body, before the recovery envelope

// --- Types ---

/**
 * v3 cleartext header — crypto params ONLY. Everything identity-bearing lives in
 * the encrypted VaultContents and is authenticated by GCM before it is shown.
 */
export interface VaultHeader {
  format: 'svrnty-vault';
  version: 3 | 4; // v4 = dual-envelope (recovery outside the passphrase layer); v3 read-only
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

/** MAGIC ‖ headerBytes — the AAD that binds header (version + params) to the body.
 *  The magic is passed in so v3 (MAGIC_V3) and v4 (MAGIC_V4) bind their own version. */
function buildAad(magic: Uint8Array, headerBytes: Uint8Array): Uint8Array {
  const aad = new Uint8Array(MAGIC_LEN + headerBytes.length);
  aad.set(magic, 0);
  aad.set(headerBytes, MAGIC_LEN);
  return aad;
}

/** Write a big-endian uint32 at offset. */
function writeUint32BE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

/** Read a big-endian uint32 at offset. */
function readUint32BE(buf: Uint8Array, offset: number): number {
  return (
    ((buf[offset] << 24) |
      (buf[offset + 1] << 16) |
      (buf[offset + 2] << 8) |
      buf[offset + 3]) >>>
    0
  );
}

/** Read the big-endian uint32 header length that follows the magic. */
function readHeaderLen(bytes: Uint8Array): number {
  return readUint32BE(bytes, MAGIC_LEN);
}

/**
 * Defensive shape check for the recovery envelope — the untrusted parse surface
 * of extractRecoveryVault. A real KeyVault (recovery.ts) carries these string
 * fields; decryptVault still does the real authentication (GCM + master hash).
 */
function isKeyVaultLike(x: unknown): x is KeyVault {
  if (typeof x !== 'object' || x === null) return false;
  const v = x as Record<string, unknown>;
  return (
    typeof v.encrypted_keys === 'string' &&
    typeof v.iv === 'string' &&
    typeof v.master_secret_hash === 'string'
  );
}

/**
 * Defensive shape check for a GraphVault (recovery.ts) — the untrusted parse
 * surface of extractGraphVault. decryptGraphVault does the real authentication
 * (GCM + master-secret hash); this only gates "looks like a graph vault".
 */
function isGraphVaultLike(x: unknown): x is GraphVault {
  if (typeof x !== 'object' || x === null) return false;
  const v = x as Record<string, unknown>;
  return (
    typeof v.encrypted_graph === 'string' &&
    typeof v.iv === 'string' &&
    typeof v.master_secret_hash === 'string'
  );
}

/**
 * Serialize the recovery KeyVault for the v4 recovery envelope. Returns 0 bytes
 * when no recovery vault is configured (recovery === null) — a valid v4 file with
 * no seed/guardian recovery. The KeyVault is ALREADY master-encrypted; we only
 * relocate it outside the passphrase layer, we do not re-encrypt it.
 *
 * graph_vault (optional): the social graph, sealed under the SAME master secret.
 * BACKWARD-COMPAT (Flint format-tier ruling): the envelope stays KeyVault-shaped, so
 * an OLD extractRecoveryVault (isKeyVaultLike) still finds the KeyVault and simply
 * ignores the extra field. graph_vault rides as an OPTIONAL sibling at the same
 * passphrase-free tier — a NEW reader finds it, an OLD one skips it; no MAGIC or
 * version bump. It only rides when a recovery KeyVault exists, since its master
 * secret is exactly what seed/Shamir reconstruct to open the graph.
 */
function serializeRecoveryEnvelope(
  recovery: unknown | null,
  graphVault?: GraphVault | null,
): Uint8Array {
  if (!isKeyVaultLike(recovery)) return new Uint8Array(0);
  const envelope = isGraphVaultLike(graphVault)
    ? { ...(recovery as Record<string, unknown>), graph_vault: graphVault }
    : recovery;
  return new TextEncoder().encode(JSON.stringify(envelope));
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
 * Pack a vault into a .svrnty v4 file (ArrayBuffer).
 * Layout: MAGIC ‖ HEADER_LEN ‖ HEADER ‖ BODY_LEN ‖ BODY ‖ RECOVERY.
 * Header = crypto params only (cleartext). Body = Argon2id + AES-256-GCM, header
 * bound as AAD. RECOVERY = the recovery KeyVault, master-encrypted, carried
 * OUTSIDE the passphrase layer so recover-after-loss works (see the v4 note up
 * top). packVault always writes v4; unpackVault still reads v3 for migration.
 */
export async function packVault(
  contents: VaultContents,
  passphrase: string,
  graphVault?: GraphVault | null,
): Promise<ArrayBuffer> {
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
    version: 4,
    kdf,
    iv: toBase64(iv),
  };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const aad = buildAad(MAGIC_V4, headerBytes);

  // Derive + encrypt body (contents holds the identity, keys, safe word, and a
  // copy of the recovery KeyVault — the daily-unlock path is unchanged).
  const key = deriveKeyArgon2id(passphrase, salt, kdf);
  const bodyBytes = await aesGcmEncrypt(
    key,
    iv,
    new TextEncoder().encode(JSON.stringify(contents)),
    aad,
  );
  key.fill(0);

  // ★ v4 recovery envelope: the SAME recovery KeyVault, carried a second time
  // OUTSIDE the passphrase body so it can be extracted with no passphrase. It is
  // already master-encrypted (encryptVault). Empty when no recovery is configured.
  const recoveryBytes = serializeRecoveryEnvelope(contents.recovery, graphVault);

  // Pack: MAGIC(8) + HEADER_LEN(4) + HEADER + BODY_LEN(4) + BODY + RECOVERY(rest)
  const totalLen =
    MAGIC_LEN +
    HEADER_LEN_SIZE +
    headerBytes.length +
    BODY_LEN_SIZE +
    bodyBytes.length +
    recoveryBytes.length;
  const result = new Uint8Array(totalLen);

  let offset = 0;
  result.set(MAGIC_V4, offset);
  offset += MAGIC_LEN;

  writeUint32BE(result, offset, headerBytes.length);
  offset += HEADER_LEN_SIZE;

  result.set(headerBytes, offset);
  offset += headerBytes.length;

  writeUint32BE(result, offset, bodyBytes.length);
  offset += BODY_LEN_SIZE;

  result.set(bodyBytes, offset);
  offset += bodyBytes.length;

  result.set(recoveryBytes, offset);

  return result.buffer;
}

/**
 * Read the cleartext header from a .svrnty v3/v4 file WITHOUT the passphrase.
 * Headers carry only crypto params — there is nothing identity-bearing to
 * preview. Use this only to confirm "this is a svrnty vault" (and which version)
 * before prompting for the passphrase. A v2/unknown file is refused with an
 * actionable message.
 */
export function readVaultHeader(data: ArrayBuffer): VaultHeader {
  const bytes = new Uint8Array(data);

  if (!magicMatches(bytes, MAGIC_V4) && !magicMatches(bytes, MAGIC_V3)) {
    refuseLegacyOrUnknown(bytes);
  }

  const headerLen = readHeaderLen(bytes);
  const headerStart = MAGIC_LEN + HEADER_LEN_SIZE;
  const headerBytes = bytes.slice(headerStart, headerStart + headerLen);
  const header = JSON.parse(new TextDecoder().decode(headerBytes));

  if (header.format !== 'svrnty-vault' || (header.version !== 3 && header.version !== 4)) {
    throw new Error(`Unsupported vault format: ${header.format} v${header.version}`);
  }

  return header as VaultHeader;
}

/**
 * Decrypt and unpack a .svrnty v3 or v4 vault file (the daily passphrase path).
 * Throws on a wrong passphrase, a corrupted file, or ANY tamper on the header
 * (the header is AAD-bound to the body). v4 length-prefixes the body (a recovery
 * envelope follows it); v3's body runs to EOF. The v4 recovery envelope is NOT
 * read here — it is extracted passphrase-free via extractRecoveryVault.
 */
export async function unpackVault(
  data: ArrayBuffer,
  passphrase: string,
): Promise<{ header: VaultHeader; contents: VaultContents }> {
  const bytes = new Uint8Array(data);

  const isV4 = magicMatches(bytes, MAGIC_V4);
  const isV3 = magicMatches(bytes, MAGIC_V3);
  if (!isV4 && !isV3) {
    refuseLegacyOrUnknown(bytes);
  }
  const magic = isV4 ? MAGIC_V4 : MAGIC_V3;

  const headerLen = readHeaderLen(bytes);
  const headerStart = MAGIC_LEN + HEADER_LEN_SIZE;
  const headerBytes = bytes.slice(headerStart, headerStart + headerLen);
  const header = JSON.parse(new TextDecoder().decode(headerBytes)) as VaultHeader;

  const expectedVersion = isV4 ? 4 : 3;
  if (header.format !== 'svrnty-vault' || header.version !== expectedVersion) {
    throw new Error(`Unsupported vault format: ${header.format} v${header.version}`);
  }

  // F1: clamp/reject hostile KDF params BEFORE deriveKey — import is the
  // untrusted surface; a param-bomb would OOM/hang the browser on restore.
  assertParamsWithinLimits(header.kdf);

  const salt = fromBase64(header.kdf.salt);
  const iv = fromBase64(header.iv);

  // v4 length-prefixes the body (BODY_LEN) so the recovery envelope can follow it;
  // v3's body runs to EOF. A tampered BODY_LEN fails closed at the GCM tag below.
  let bodyBytes: Uint8Array;
  if (isV4) {
    const bodyLenOffset = headerStart + headerLen;
    const bodyLen = readUint32BE(bytes, bodyLenOffset);
    const bodyStart = bodyLenOffset + BODY_LEN_SIZE;
    bodyBytes = bytes.slice(bodyStart, bodyStart + bodyLen);
  } else {
    bodyBytes = bytes.slice(headerStart + headerLen);
  }

  // AAD must be byte-identical to pack time: MAGIC ‖ the exact header bytes.
  const aad = buildAad(magic, headerBytes);

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

// --- Recovery Envelope (passphrase-free) ---

/**
 * Extract the recovery KeyVault from a .svrnty v4 file WITHOUT the passphrase.
 * This is the passphrase-free half of the dual envelope — it enables
 * recover-after-loss: lost passphrase → recover via seed phrase or guardian
 * shards. The returned KeyVault is still master-encrypted; it yields the private
 * keys only to recoverFromSeedPhrase(kv, phrase) or recoverFromShards(kv, shards),
 * which supply the master secret. Do NOT pass a passphrase here — by design this
 * path needs none.
 *
 * v3 files carry no recovery envelope; they are refused with an actionable
 * message (re-export to a v4 backup to enable passphrase-free recovery).
 */
export function extractRecoveryVault(data: ArrayBuffer): KeyVault {
  const bytes = new Uint8Array(data);

  if (magicMatches(bytes, MAGIC_V3)) {
    throw new Error(
      'This backup predates seed recovery (v3). It can be restored only with ' +
        'its passphrase. Open your identity and re-export to enable ' +
        'passphrase-free recovery.',
    );
  }
  if (!magicMatches(bytes, MAGIC_V4)) {
    refuseLegacyOrUnknown(bytes);
  }

  // Layout: MAGIC(8) HEADER_LEN(4) HEADER BODY_LEN(4) BODY RECOVERY(rest).
  // Bounds-check every step — a truncated/hostile file must fail closed, never
  // read past the buffer or return a partial envelope.
  if (bytes.length < MAGIC_LEN + HEADER_LEN_SIZE) {
    throw new Error('Corrupted .svrnty file — truncated header');
  }
  const headerLen = readHeaderLen(bytes);
  const bodyLenOffset = MAGIC_LEN + HEADER_LEN_SIZE + headerLen;
  if (bytes.length < bodyLenOffset + BODY_LEN_SIZE) {
    throw new Error('Corrupted .svrnty file — truncated body length');
  }
  const bodyLen = readUint32BE(bytes, bodyLenOffset);
  const recoveryStart = bodyLenOffset + BODY_LEN_SIZE + bodyLen;
  if (bytes.length < recoveryStart) {
    throw new Error('Corrupted .svrnty file — truncated body');
  }

  const recoveryBytes = bytes.slice(recoveryStart);
  if (recoveryBytes.length === 0) {
    throw new Error(
      'This backup has no recovery vault — seed/guardian recovery was not set ' +
        'up for this identity.',
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(recoveryBytes));
  } catch {
    throw new Error('The recovery vault in this backup is unreadable (corrupted).');
  }
  if (!isKeyVaultLike(parsed)) {
    throw new Error('The recovery vault in this backup is malformed.');
  }
  return parsed;
}

/**
 * Extract the social-graph vault from a .svrnty v4 file WITHOUT the passphrase —
 * the twin of extractRecoveryVault, at the SAME passphrase-free tier. Returns null
 * (NEVER throws) whenever a graph_vault is absent or unreadable: an old v3 file, a
 * v4 file with no recovery envelope, a v4 envelope that predates graph_vault, or a
 * corrupted section. This is the Do-No-Harm line — a backup without a graph_vault
 * must restore EXACTLY as before (keys only): no error, no data touched.
 *
 * A returned GraphVault is still master-encrypted; decryptGraphVault(gv, masterSecret)
 * — masterSecret from the seed phrase or Shamir shards — yields the graph. Do NOT
 * pass a passphrase here; by design this path needs none.
 */
export function extractGraphVault(data: ArrayBuffer): GraphVault | null {
  const bytes = new Uint8Array(data);

  // Only v4 carries a passphrase-free envelope tier. v3/v2/unknown → no graph.
  if (!magicMatches(bytes, MAGIC_V4)) return null;

  // Bounds-check every step; a truncated/hostile file fails to null, never throws.
  if (bytes.length < MAGIC_LEN + HEADER_LEN_SIZE) return null;
  const headerLen = readHeaderLen(bytes);
  const bodyLenOffset = MAGIC_LEN + HEADER_LEN_SIZE + headerLen;
  if (bytes.length < bodyLenOffset + BODY_LEN_SIZE) return null;
  const bodyLen = readUint32BE(bytes, bodyLenOffset);
  const recoveryStart = bodyLenOffset + BODY_LEN_SIZE + bodyLen;
  if (bytes.length < recoveryStart) return null;

  const recoveryBytes = bytes.slice(recoveryStart);
  if (recoveryBytes.length === 0) return null; // no recovery envelope → no graph

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(recoveryBytes));
  } catch {
    return null; // unreadable envelope → treat as absent (do-no-harm)
  }
  if (typeof parsed !== 'object' || parsed === null) return null;

  const gv = (parsed as Record<string, unknown>).graph_vault;
  return isGraphVaultLike(gv) ? gv : null; // absent or malformed → null
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
