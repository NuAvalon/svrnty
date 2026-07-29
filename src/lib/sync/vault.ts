// src/lib/sync/vault.ts
// Unified vault format — one encrypted file, everything inside.
// Like KeePass .kdbx but for sovereign identity + trust graph.
//
// File format:
//   MAGIC (8 bytes): "SVRNTY\x00\x02"
//   HEADER_LEN (4 bytes): uint32 big-endian
//   HEADER (variable): JSON, unencrypted — safe word, fingerprint hint
//   BODY: AES-256-GCM encrypted via backup.ts scheme
//
// The header is readable without the passphrase so the UI can show
// the safe word and fingerprint hint before the user types anything.

import { encryptBackup, decryptBackup } from './backup';
import type { TrustGraph, TrustEdge } from '../trust/types';

// --- Magic bytes ---
const MAGIC = new Uint8Array([0x53, 0x56, 0x52, 0x4E, 0x54, 0x59, 0x00, 0x02]); // "SVRNTY\0\2"
const MAGIC_LEN = 8;
const HEADER_LEN_SIZE = 4;

// --- Types ---

export interface VaultHeader {
  format: 'svrnty-vault';
  version: 2;
  safeWord: string;                 // user-chosen, shown before passphrase entry
  fingerprintHint: string;          // last 8 chars of fingerprint
  displayName: string;              // user's name for quick identification
  createdAt: string;
  lastModified: string;
  entryCount: number;               // contacts count — helps user confirm right vault
  deviceId: string;                 // which device last modified this vault
}

export interface VaultContents {
  identity: VaultIdentity;
  keys: VaultKeys;
  trustGraph: TrustGraph;
  settings: VaultSettings;
  recovery: any | null;             // KeyVault (Shamir shards metadata)
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
  pq: any | null;                   // serialized PQ keypair bundle
}

export interface VaultSettings {
  defaultDecayDays: number;         // default: 730 (2 years)
  safeWord: string;                 // stored here too for consistency
  cloudSync?: {
    provider: 'local-file' | 'google-drive' | 'dropbox' | 'icloud' | 'webdav' | null;
    autoSync: boolean;
    lastSync: string | null;
    remoteFileId?: string;          // provider-specific file ID
    webdavUrl?: string;             // for WebDAV only
  };
}

export interface Tombstone {
  id: string;                       // ID of deleted entry
  deletedAt: string;
  deletedBy: string;                // device ID
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
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Create a new vault from identity data.
 */
export function createVaultContents(
  identity: VaultIdentity,
  keys: VaultKeys,
  trustGraph: TrustGraph,
  settings: Partial<VaultSettings> = {},
  recovery: any | null = null,
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

/**
 * Build the unencrypted header from vault contents.
 */
export function buildHeader(contents: VaultContents): VaultHeader {
  const fp = contents.identity.identity.fingerprint;
  return {
    format: 'svrnty-vault',
    version: 2,
    safeWord: contents.settings.safeWord,
    fingerprintHint: fp.slice(-8),
    displayName: contents.identity.identity.name,
    createdAt: contents.identity.created_at,
    lastModified: contents.sync.lastModified,
    entryCount: contents.trustGraph.edges?.length ?? 0,
    deviceId: contents.sync.deviceId,
  };
}

// --- Vault Serialization ---

/**
 * Pack a vault into a .svrnty file (ArrayBuffer).
 * The header is unencrypted. The body is AES-256-GCM encrypted.
 */
export async function packVault(
  contents: VaultContents,
  passphrase: string
): Promise<ArrayBuffer> {
  // Update lastModified
  contents.sync.lastModified = new Date().toISOString();

  // Build header
  const header = buildHeader(contents);
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));

  // Encrypt body
  const encryptedBody = await encryptBackup(contents, passphrase);
  const bodyBytes = new Uint8Array(encryptedBody);

  // Pack: MAGIC(8) + HEADER_LEN(4) + HEADER(variable) + BODY(variable)
  const totalLen = MAGIC_LEN + HEADER_LEN_SIZE + headerBytes.length + bodyBytes.length;
  const result = new Uint8Array(totalLen);

  let offset = 0;

  // Magic
  result.set(MAGIC, offset);
  offset += MAGIC_LEN;

  // Header length (uint32 big-endian)
  const headerLen = headerBytes.length;
  result[offset] = (headerLen >> 24) & 0xff;
  result[offset + 1] = (headerLen >> 16) & 0xff;
  result[offset + 2] = (headerLen >> 8) & 0xff;
  result[offset + 3] = headerLen & 0xff;
  offset += HEADER_LEN_SIZE;

  // Header
  result.set(headerBytes, offset);
  offset += headerBytes.length;

  // Encrypted body
  result.set(bodyBytes, offset);

  return result.buffer;
}

/**
 * Read the unencrypted header from a .svrnty file.
 * Use this to show the safe word BEFORE asking for the passphrase.
 */
export function readVaultHeader(data: ArrayBuffer): VaultHeader {
  const bytes = new Uint8Array(data);

  // Verify magic
  for (let i = 0; i < MAGIC_LEN; i++) {
    if (bytes[i] !== MAGIC[i]) {
      throw new Error('Not a valid .svrnty vault file');
    }
  }

  // Read header length
  const headerLen =
    (bytes[MAGIC_LEN] << 24) |
    (bytes[MAGIC_LEN + 1] << 16) |
    (bytes[MAGIC_LEN + 2] << 8) |
    bytes[MAGIC_LEN + 3];

  // Read header JSON
  const headerStart = MAGIC_LEN + HEADER_LEN_SIZE;
  const headerBytes = bytes.slice(headerStart, headerStart + headerLen);
  const header = JSON.parse(new TextDecoder().decode(headerBytes));

  // Validate
  if (header.format !== 'svrnty-vault' || header.version !== 2) {
    throw new Error(`Unsupported vault format: ${header.format} v${header.version}`);
  }

  return header as VaultHeader;
}

/**
 * Decrypt and unpack a .svrnty vault file.
 */
export async function unpackVault(
  data: ArrayBuffer,
  passphrase: string
): Promise<{ header: VaultHeader; contents: VaultContents }> {
  const bytes = new Uint8Array(data);

  // Read header (validates magic)
  const header = readVaultHeader(data);

  // Read header length again to find body offset
  const headerLen =
    (bytes[MAGIC_LEN] << 24) |
    (bytes[MAGIC_LEN + 1] << 16) |
    (bytes[MAGIC_LEN + 2] << 8) |
    bytes[MAGIC_LEN + 3];

  // Body starts after magic + header_len + header
  const bodyStart = MAGIC_LEN + HEADER_LEN_SIZE + headerLen;
  const bodyBytes = bytes.slice(bodyStart);

  // Decrypt body
  const contents = await decryptBackup(bodyBytes.buffer, passphrase) as VaultContents;

  return { header, contents };
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
