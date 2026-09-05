// src/lib/identity/client-store.ts
// Client-side IndexedDB storage for sovereign identity
// Replaces server-side fs operations — all data stays in the user's browser

// C2 / Invariant-1: the ONE crypto import this storage layer takes —
// a fail-closed fingerprint↔key binding check so no caller can persist a forged contact.
import { fingerprintMatchesKey } from './fingerprint';
// Type-only (erased at compile — no runtime import, no cycle): the shape importVaultContents persists.
import type { VaultContents } from '../sync/vault';

const DB_NAME = 'svrnty';
const DB_VERSION = 3;

// ── Session key management (F1 fix: encrypt keys at rest in IndexedDB) ──
// The session key is a non-extractable CryptoKey held in memory.
// It's derived from the user's passphrase via PBKDF2 (600K iterations SHA-256).
// Lost on tab close/refresh — user must re-enter passphrase to unlock.

let _sessionKey: CryptoKey | null = null;
let _sessionSalt: Uint8Array | null = null;

const PBKDF2_ITERATIONS = 600_000;
const ENC_VERSION = 1; // Encrypted record format version

interface EncryptedKeyRecord {
  fingerprint: string;
  enc_version: number;
  salt: string;    // base64, PBKDF2 salt
  iv: string;      // base64, AES-GCM nonce
  ciphertext: string; // base64, AES-GCM encrypted {privateKey, passphrase}
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveSessionKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Initialize the session key from a user passphrase.
 * Call once per session (on identity creation or unlock).
 * The derived CryptoKey is held in memory — lost on tab close.
 */
export async function initSessionKey(passphrase: string): Promise<void> {
  // Check if we have an existing salt stored for this browser
  const setting = await txGet<{ key: string; value: string }>('settings', 'key_encryption_salt');
  let salt: Uint8Array;
  if (setting?.value) {
    salt = fromBase64(setting.value);
  } else {
    salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    await txPut('settings', { key: 'key_encryption_salt', value: toBase64(salt) });
  }
  _sessionKey = await deriveSessionKey(passphrase, salt);
  _sessionSalt = salt;
}

/** Check if the session is unlocked (key available in memory). */
export function isSessionUnlocked(): boolean {
  return _sessionKey !== null;
}

/** Lock the session — clear the key from memory. */
export function lockSession(): void {
  _sessionKey = null;
  _sessionSalt = null;
}

async function encryptKeyData(data: { privateKey: string; passphrase: string }): Promise<Omit<EncryptedKeyRecord, 'fingerprint'>> {
  if (!_sessionKey) throw new Error('Session locked — call initSessionKey() first');
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, _sessionKey, plaintext)
  );
  return {
    enc_version: ENC_VERSION,
    salt: toBase64(_sessionSalt!),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };
}

async function decryptKeyData(record: EncryptedKeyRecord): Promise<{ privateKey: string; passphrase: string }> {
  if (!_sessionKey) throw new Error('Session locked — call initSessionKey() first');
  const iv = fromBase64(record.iv);
  const ciphertext = fromBase64(record.ciphertext);
  try {
    const decrypted = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, _sessionKey, ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch {
    throw new Error('Decryption failed — wrong passphrase');
  }
}

interface IdentityRecord {
  fingerprint: string;
  data: any; // IdentityData
  created_at: string;
}

interface KeyRecord {
  fingerprint: string;
  privateKey: string;
  passphrase: string;
}

interface PQKeyRecord {
  fingerprint: string;
  bundle: any; // serialized PQ keypair bundle
}

interface VaultRecord {
  fingerprint: string;
  vault: any; // KeyVault
}

export interface ContactRecord {
  id: string;
  fingerprint: string;
  name: string;
  email: string;
  public_key: string;
  // ── Post-quantum keys (0.12 pq-carry) ───────────────────────────────────────
  // Stored ONLY from a card whose signature verified against the fp-bound classical key
  // (fail-closed §4 branch 4). A card with no/invalid signature drops these (branches 2/3) —
  // an unauthenticated pq_kem is NEVER stored. Both are projected → TrustEdge.peer_pq_*.
  pq_sig_public_key?: string;   // ML-DSA base64
  pq_kem_public_key?: string;   // ML-KEM base64 — the HNDL-protected encryption key
  trust_level: string;
  added_at: string;
  metadata?: any;

  // ── 0.14 verify bookkeeping ──────────────────────────
  // epoch/version mirror the wire identity_epoch/revision a verified contact.update
  // carried (written by applyVerifiedContactUpdate). Peer-authored wire data — the
  // monotonic/replay floors read them; safe to carry.
  epoch?: number;
  version?: number;

  // ── LOCAL-ONLY decay clock (guardrail A) ────────────────────
  // last_interaction is DERIVED LOCALLY (the receiver's own witnessed-receipt: apply
  // sets it = now on a VerifiedContactUpdate). It is NEVER signed and MUST NEVER enter
  // an outbound payload to a peer or the relay — leaking it would turn a private decay
  // clock into a third-party activity oracle. Audited clean 2026-08-17: the only
  // peer/relay outbound (Ceremony.buildCardPackage) sends a closed
  // {fingerprint,display_name,public_key,email} from OWN identity; contact.update can't
  // carry it (not allowlisted); owner's-own vault/file export is own-data, not a peer
  // broadcast. Any NEW outbound path must exclude this field.
  last_interaction?: string;

  [key: string]: any;
}

// ── Social-recovery shard types (the "tear") ─────────────────────

/** Relay payload discriminator for a shard entrusted to a contact. Single
 *  source of truth shared by the give side (ShardGiveDialog) and the receive
 *  side (app/c/[code]) — a mismatch would misroute a shard into contact-import. */
export const SHARD_CUSTODY_TYPE = 'svrnty-shard-custody';
// A shard is one piece of an M-of-N Shamir split of the master secret
// (see lib/crypto/recovery.ts). Structurally mirrored here to keep
// client-store dependency-light (no crypto import).

/** One recipient a shard was given to. */
interface ShardCustody {
  contact_id: string;
  name: string;
  fingerprint: string;
}

/** A shard I hold for MY OWN identity, plus who (if anyone) I gave it to. */
interface StoredShard {
  index: number;
  data: string;                 // base64 shard bytes
  identity_fingerprint: string; // whose vault this reconstructs (mine)
  threshold: number;
  given_to?: ShardCustody;
  given_at?: string;
}

/** All shards for one of my identities. */
interface ShardsData {
  threshold: number;
  total: number;
  shards: StoredShard[];
}

/** A shard someone else entrusted to me (I am the custodian). */
interface HeldShardRecord {
  id: string;
  holder_fingerprint: string;   // me (the custodian)
  owner_fingerprint: string;    // whose recovery this shard belongs to
  owner_name: string;
  shard: any;                   // the raw Shard object from the giver
  threshold: number;
  total: number;
  received_at: string;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      if (!db.objectStoreNames.contains('identities')) {
        db.createObjectStore('identities', { keyPath: 'fingerprint' });
      }
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys', { keyPath: 'fingerprint' });
      }
      if (!db.objectStoreNames.contains('pq_keys')) {
        db.createObjectStore('pq_keys', { keyPath: 'fingerprint' });
      }
      if (!db.objectStoreNames.contains('vaults')) {
        db.createObjectStore('vaults', { keyPath: 'fingerprint' });
      }
      if (!db.objectStoreNames.contains('contacts')) {
        const contactStore = db.createObjectStore('contacts', { keyPath: 'id' });
        contactStore.createIndex('fingerprint', 'fingerprint', { unique: true });
        contactStore.createIndex('owner', 'owner_fingerprint', { unique: false });
      }
      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings', { keyPath: 'key' });
      }
      // v3: social-recovery shards. `shards` = MY vault's shards (one record per
      // identity, keyed by fingerprint) with per-shard give-custody. `held_shards`
      // = shards OTHERS entrusted to me (the receiving side of "the tear").
      if (!db.objectStoreNames.contains('shards')) {
        db.createObjectStore('shards', { keyPath: 'fingerprint' });
      }
      if (!db.objectStoreNames.contains('held_shards')) {
        const heldStore = db.createObjectStore('held_shards', { keyPath: 'id' });
        heldStore.createIndex('holder', 'holder_fingerprint', { unique: false });
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      // If another tab opens a newer DB version, yield this connection so its
      // upgrade isn't blocked (paired with onblocked below).
      db.onversionchange = () => { db.close(); };
      resolve(db);
    };
    request.onerror = () => reject(request.error);
    // Without this, a version upgrade blocked by another open connection hangs
    // open() forever — freezing the app at its "RESOLVING…" loading state.
    // Settling the promise lets the caller degrade gracefully instead.
    request.onblocked = () => reject(new Error('svrnty database is upgrading — close other svrnty tabs and reload'));
  });
}

async function txGet<T>(storeName: string, key: string): Promise<T | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const request = store.get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
  });
}

async function txPut<T>(storeName: string, value: T): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    store.put(value);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function txDelete(storeName: string, key: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    store.delete(key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function txGetAll<T>(storeName: string): Promise<T[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const request = store.getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
  });
}

async function txGetByIndex<T>(storeName: string, indexName: string, key: string): Promise<T[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const index = store.index(indexName);
    const request = index.getAll(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
  });
}

// ── Identity operations ──────────────────────────────────────────

export async function storeIdentity(fingerprint: string, data: any): Promise<void> {
  await txPut('identities', {
    fingerprint,
    data,
    created_at: data.created_at || new Date().toISOString(),
  });
}

export async function loadIdentity(fingerprint: string): Promise<any | null> {
  const record = await txGet<IdentityRecord>('identities', fingerprint);
  const data = record?.data ?? null;
  // Guard against corrupt records missing required fields
  if (data && !data.identity?.fingerprint) return null;
  return data;
}

export async function getActiveFingerprint(): Promise<string | null> {
  const setting = await txGet<{ key: string; value: string }>('settings', 'active_fingerprint');
  return setting?.value ?? null;
}

export async function setActiveFingerprint(fingerprint: string): Promise<void> {
  await txPut('settings', { key: 'active_fingerprint', value: fingerprint });
}

export async function listIdentities(): Promise<IdentityRecord[]> {
  return txGetAll('identities');
}

// ── Key operations ──────────────────────────────────────────────

export async function storeKey(fingerprint: string, privateKey: string, passphrase: string): Promise<void> {
  if (_sessionKey) {
    // Encrypt before storing
    const encrypted = await encryptKeyData({ privateKey, passphrase });
    await txPut('keys', { fingerprint, ...encrypted });
  } else {
    // Fallback: store unencrypted (legacy / during initial setup before session key exists)
    await txPut('keys', { fingerprint, privateKey, passphrase });
  }
}

export async function loadKey(fingerprint: string): Promise<{ privateKey: string; passphrase: string } | null> {
  const record = await txGet<any>('keys', fingerprint);
  if (!record) return null;

  // Detect encrypted vs legacy unencrypted records
  if (record.enc_version === ENC_VERSION) {
    // Encrypted record — decrypt
    return decryptKeyData(record as EncryptedKeyRecord);
  }

  // Legacy unencrypted record — return as-is
  // Auto-migrate: re-encrypt if session key is available
  if (_sessionKey && record.privateKey) {
    const encrypted = await encryptKeyData({ privateKey: record.privateKey, passphrase: record.passphrase });
    await txPut('keys', { fingerprint, ...encrypted });
  }

  return { privateKey: record.privateKey, passphrase: record.passphrase };
}

// ── PQ key operations ────────────────────────────────────────────

export async function storePQKeys(fingerprint: string, bundle: any): Promise<void> {
  if (_sessionKey) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(bundle), passphrase: '' });
    await txPut('pq_keys', { fingerprint, ...encrypted });
  } else {
    await txPut('pq_keys', { fingerprint, bundle });
  }
}

export async function loadPQKeys(fingerprint: string): Promise<any | null> {
  const record = await txGet<any>('pq_keys', fingerprint);
  if (!record) return null;

  if (record.enc_version === ENC_VERSION) {
    const decrypted = await decryptKeyData(record as EncryptedKeyRecord);
    return JSON.parse(decrypted.privateKey);
  }

  // Legacy unencrypted — auto-migrate if session key available
  if (_sessionKey && record.bundle) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(record.bundle), passphrase: '' });
    await txPut('pq_keys', { fingerprint, ...encrypted });
  }

  return record.bundle ?? null;
}

// ── Vault operations ─────────────────────────────────────────────

export async function storeVault(fingerprint: string, vault: any): Promise<void> {
  if (_sessionKey) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(vault), passphrase: '' });
    await txPut('vaults', { fingerprint, ...encrypted });
  } else {
    await txPut('vaults', { fingerprint, vault });
  }
}

export async function loadVault(fingerprint: string): Promise<any | null> {
  const record = await txGet<any>('vaults', fingerprint);
  if (!record) return null;

  if (record.enc_version === ENC_VERSION) {
    const decrypted = await decryptKeyData(record as EncryptedKeyRecord);
    return JSON.parse(decrypted.privateKey);
  }

  // Legacy unencrypted — auto-migrate if session key available
  if (_sessionKey && record.vault) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(record.vault), passphrase: '' });
    await txPut('vaults', { fingerprint, ...encrypted });
  }

  return record.vault ?? null;
}

// ── Shard operations (social recovery — "the tear") ──────────────
// My own shards are key material → encrypted at rest like the vault
// when a session key is present (falls back to plaintext pre-unlock,
// same as keys/vaults).

/** Persist all shards for one of my identities (stops the create-time discard). */
export async function storeShards(fingerprint: string, shardsData: ShardsData): Promise<void> {
  if (_sessionKey) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(shardsData), passphrase: '' });
    await txPut('shards', { fingerprint, ...encrypted });
  } else {
    await txPut('shards', { fingerprint, shards_data: shardsData });
  }
}

export async function loadShards(fingerprint: string): Promise<ShardsData | null> {
  const record = await txGet<any>('shards', fingerprint);
  if (!record) return null;

  if (record.enc_version === ENC_VERSION) {
    const decrypted = await decryptKeyData(record as EncryptedKeyRecord);
    return JSON.parse(decrypted.privateKey);
  }

  // Legacy unencrypted — auto-migrate if session key available
  if (_sessionKey && record.shards_data) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(record.shards_data), passphrase: '' });
    await txPut('shards', { fingerprint, ...encrypted });
  }

  return record.shards_data ?? null;
}

/**
 * Record that a shard was torn off and given to a contact.
 * Returns the updated ShardsData. Throws if the identity has no shards
 * or the index is unknown.
 */
export async function markShardGiven(
  fingerprint: string,
  shardIndex: number,
  contact: ShardCustody,
): Promise<ShardsData> {
  const data = await loadShards(fingerprint);
  if (!data) throw new Error('No shards found for this identity');
  const shard = data.shards.find(s => s.index === shardIndex);
  if (!shard) throw new Error(`Shard #${shardIndex} not found`);
  shard.given_to = contact;
  shard.given_at = new Date().toISOString();
  await storeShards(fingerprint, data);
  return data;
}

/** Store a shard someone entrusted to me (the receiving side of the tear). */
export async function storeHeldShard(
  holderFingerprint: string,
  held: Omit<HeldShardRecord, 'id' | 'holder_fingerprint' | 'received_at'>,
): Promise<HeldShardRecord> {
  const record: HeldShardRecord = {
    ...held,
    id: crypto.randomUUID(),
    holder_fingerprint: holderFingerprint,
    received_at: new Date().toISOString(),
  };
  await txPut('held_shards', record);
  return record;
}

/** List shards I am holding on behalf of others. */
export async function getHeldShards(holderFingerprint: string): Promise<HeldShardRecord[]> {
  return txGetByIndex('held_shards', 'holder', holderFingerprint);
}

// ── Contact operations ───────────────────────────────────────────

export async function addContact(ownerFingerprint: string, contact: Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'>): Promise<ContactRecord> {
  // Invariant-1: a fingerprint exists only with a bound key.
  // Keyless rows MUST NOT carry a fingerprint (even a placeholder).
  const pk = (contact.public_key || '').trim();
  if (!pk) {
    contact = { ...contact, fingerprint: '', public_key: '' };
  } else if (!(await fingerprintMatchesKey(contact.fingerprint, pk))) {
    // C2 / Invariant-1: fail-closed when a key is present —
    // refuse mismatched attacker-key + victim-fingerprint pairs.
    throw new Error('fingerprint↔key binding failed — refusing to store a contact whose fingerprint does not match its public key');
  }
  const id = crypto.randomUUID();
  const record: ContactRecord = {
    ...contact,
    id,
    owner_fingerprint: ownerFingerprint,
    added_at: new Date().toISOString(),
  };
  // Keyless/gray contacts (vCard import) have no fingerprint. The `contacts.fingerprint` index is
  // UNIQUE: IndexedDB collides multiple ''-valued keys, but SKIPS records whose key is ABSENT. So a
  // second gray with fingerprint='' throws a ConstraintError — store an empty fingerprint as absent
  // instead. (Verified in-browser: two ''-fp puts → 2nd errors; two absent-fp puts → both OK.)
  if (!record.fingerprint) delete (record as { fingerprint?: string }).fingerprint;
  if (!(record.public_key || '').trim()) delete (record as { public_key?: string }).public_key;
  try {
    await txPut('contacts', record);
  } catch (e) {
    // Idempotent-by-fingerprint (fix at the source, not per-caller): two concurrent
    // add-paths for the same joiner (interval poll vs Galaxy pull-to-refresh; a future websocket live-add)
    // can each pass a getContactByFingerprint pre-check as null, then both insert. The UNIQUE fingerprint
    // index (contacts store) catches the 2nd → ConstraintError. Rather than surface that caught error,
    // return the record that WON the race — exactly one contact, no duplicate, no error, every add-path
    // safe by construction. Fetch runs in a fresh db/transaction (txPut closed its own), so it's clean.
    if (record.fingerprint && (e as { name?: string } | null)?.name === 'ConstraintError') {
      const existing = await getContactByFingerprint(ownerFingerprint, record.fingerprint);
      if (existing) return existing;
    }
    throw e; // any other failure (or missing existing) → preserve the fail-closed contract
  }
  return record;
}

export async function updateContact(id: string, updates: Partial<ContactRecord>): Promise<void> {
  const existing = await txGet<ContactRecord>('contacts', id);
  if (!existing) throw new Error('Contact not found');
  const next = { ...existing, ...updates, id: existing.id };
  const pk = (next.public_key || '').trim();
  // Invariant-1 back-stop: no key ⇒ no fingerprint (impossible to construct keyless fp).
  if (!pk) {
    next.public_key = '';
    delete (next as { fingerprint?: string }).fingerprint;
  } else if (!(await fingerprintMatchesKey(next.fingerprint, pk))) {
    throw new Error('fingerprint↔key binding failed — refusing to update a contact whose fingerprint does not match its public key');
  }
  await txPut('contacts', next);
}

/**
 * True if this identity's private key record is AES-GCM encrypted at rest
 * (requires initSessionKey before loadKey will succeed).
 */
export async function hasEncryptedKeys(fingerprint: string): Promise<boolean> {
  const record = await txGet<any>('keys', fingerprint);
  return !!(record && record.enc_version === ENC_VERSION);
}

/**
 * Read-only, PRE-UNLOCK-SAFE passphrase-epoch for the biometric device-unlock seam
 * (biometric-seam.ts). ADD-ONLY: touches no passphrase/recovery control flow — it is a
 * pure read of the at-rest key envelope (mirrors hasEncryptedKeys: raw txGet, no session
 * required, never returns plaintext).
 *
 * Returns a SHA-256 fingerprint of the ENCRYPTED key envelope (enc_version|salt|iv|
 * ciphertext) for `fingerprint`. This value changes IFF the key material is re-encrypted —
 * i.e. on passphrase-change / recovery-restore / vault re-key, all of which re-write the
 * `keys` record via storeKey — and is STABLE across ordinary lock/unlock cycles (a plain
 * unlock never rewrites the record). The biometric seam stamps it into the wrapped blob at
 * enroll and compares at unlock; a mismatch (or null) means the wrapped passphrase is STALE
 * and the blob MUST be invalidated (force re-enroll). Never leaves the device.
 *
 * Returns null when no key record exists OR the record is not encrypted-at-rest (legacy
 * plaintext): both are treated by the caller as "invalidate / cannot back a device-unlock".
 * The digest reveals nothing beyond what already sits in IndexedDB (it hashes ciphertext,
 * not the passphrase) — it is NOT a passphrase oracle.
 */
export async function getKeyEnvelopeFingerprint(fingerprint: string): Promise<string | null> {
  const record = await txGet<any>('keys', fingerprint);
  if (!record || record.enc_version !== ENC_VERSION) return null;
  const canonical = `v${record.enc_version}|${record.salt}|${record.iv}|${record.ciphertext}`;
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)),
  );
  return toBase64(digest);
}

export async function removeContact(id: string): Promise<void> {
  await txDelete('contacts', id);
}

export async function getContact(id: string): Promise<ContactRecord | null> {
  return txGet('contacts', id);
}

export async function getContactByFingerprint(ownerFingerprint: string, fingerprint: string): Promise<ContactRecord | null> {
  const contacts = await txGetByIndex<ContactRecord>('contacts', 'owner', ownerFingerprint);
  return contacts.find(c => c.fingerprint === fingerprint) ?? null;
}

export async function getAllContacts(ownerFingerprint: string): Promise<ContactRecord[]> {
  return txGetByIndex('contacts', 'owner', ownerFingerprint);
}

export async function searchContacts(ownerFingerprint: string, query: string): Promise<ContactRecord[]> {
  const contacts = await getAllContacts(ownerFingerprint);
  const q = query.toLowerCase();
  return contacts.filter(c =>
    c.name?.toLowerCase().includes(q) ||
    c.email?.toLowerCase().includes(q) ||
    c.fingerprint?.toLowerCase().includes(q)
  );
}

// ── Export / Import (full sovereign backup) ──────────────────────

export interface SovereignBackup {
  version: '1.0';
  exported_at: string;
  identity: any;
  keys?: { privateKey: string; passphrase: string };
  pq_keys?: any;
  vault?: any;
  shards?: ShardsData;
  contacts: ContactRecord[];
}

export async function exportAll(fingerprint: string, includePrivateKeys: boolean = false): Promise<SovereignBackup> {
  const identity = await loadIdentity(fingerprint);
  if (!identity) throw new Error('Identity not found');

  const backup: SovereignBackup = {
    version: '1.0',
    exported_at: new Date().toISOString(),
    identity,
    contacts: await getAllContacts(fingerprint),
  };

  if (includePrivateKeys) {
    backup.keys = await loadKey(fingerprint) ?? undefined;
    backup.pq_keys = await loadPQKeys(fingerprint) ?? undefined;
    backup.vault = await loadVault(fingerprint) ?? undefined;
    backup.shards = await loadShards(fingerprint) ?? undefined;
  }

  return backup;
}

export async function importAll(backup: SovereignBackup): Promise<string> {
  const fingerprint = backup.identity?.identity?.fingerprint;
  if (!fingerprint) throw new Error('Invalid backup: no fingerprint');

  await storeIdentity(fingerprint, backup.identity);

  if (backup.keys) {
    await storeKey(fingerprint, backup.keys.privateKey, backup.keys.passphrase);
  }
  if (backup.pq_keys) {
    await storePQKeys(fingerprint, backup.pq_keys);
  }
  if (backup.vault) {
    await storeVault(fingerprint, backup.vault);
  }
  if (backup.shards) {
    await storeShards(fingerprint, backup.shards);
  }

  for (const contact of (backup.contacts || [])) {
    await txPut('contacts', { ...contact, owner_fingerprint: fingerprint });
  }

  await setActiveFingerprint(fingerprint);
  return fingerprint;
}

/**
 * Persist an already-decrypted .svrnty VaultContents to IndexedDB — the
 * restore-onto-this-device / daily passphrase-unlock path. Converges to the SAME
 * at-rest state as genesis (browser-identity.ts) and the recovery-code path
 * (restoreIdentityFromSeedVault), so a passphrase restore STICKS across reload
 * instead of only hydrating in-memory state (the data-safety launch-blocker:
 * before this, "Open Vault" set React state but wrote nothing → reload = identity lost).
 *
 * SECURITY (persist SAFELY, not just persist):
 *  • Self-guarding like addContact: the identity's public_key MUST bind to `fingerprint`
 *    (fingerprintMatchesKey) — a .svrnty file is untrusted-importable, so refuse to
 *    persist a forged identity whose fingerprint does not match its key.
 *  • Contacts go through addContact, inheriting its fail-closed fingerprint↔key binding
 *    (never persist a forged contact) + keyless handling + fingerprint-idempotency.
 *  • AT-REST EQUIVALENCE: the caller MUST initSessionKey() first so keys/pq_keys/vault
 *    are encrypted at rest exactly as genesis stores them (else the plaintext fallback
 *    would be a weaker at-rest form on the restore path).
 * The caller (vaultPassphraseRestore adapter) additionally binds the PRIVATE key to the
 * fingerprint and passes the DERIVED (not merely claimed) fingerprint as `fingerprint`.
 */
export async function importVaultContents(
  contents: VaultContents,
  fingerprint: string,
): Promise<string> {
  const fp = (fingerprint || contents.identity?.identity?.fingerprint || '').trim();
  if (!fp) throw new Error('Invalid vault: no fingerprint');

  // Fail-closed identity binding (mirrors addContact): refuse a forged identity before
  // any write, so a rejected vault leaves NO partial state.
  const identityPub = contents.identity?.identity?.public_key || '';
  if (!(await fingerprintMatchesKey(fp, identityPub))) {
    throw new Error(
      'fingerprint↔key binding failed — refusing to persist an identity whose fingerprint does not match its public key',
    );
  }

  await storeIdentity(fp, contents.identity);

  const classical = contents.keys?.classical;
  if (classical?.privateKey) {
    await storeKey(fp, classical.privateKey, classical.passphrase);
  }
  if (contents.keys?.pq) {
    await storePQKeys(fp, contents.keys.pq);
  }
  // v4 dual-envelope recovery KeyVault (Shamir metadata) — the same store genesis and
  // the recovery-code path write via storeVault. Absent on v3 → skipped.
  if (contents.recovery) {
    await storeVault(fp, contents.recovery);
  }

  // Contacts / trust network ride the encrypted body as a raw ContactRecord[]
  // (VaultExportDialog stashes the exportAll contacts on trustGraph.contacts). Persist
  // each via addContact so it inherits the fail-closed binding check; the spread carries
  // the security-relevant epoch/version/pq fields — only the local id/added_at re-mint.
  // A single unbindable/malformed contact is skipped (fail-closed) rather than aborting
  // the whole restore: the identity + keys are the launch-blocker, not one bad contact.
  const contacts = (contents.trustGraph as unknown as { contacts?: any[] } | null)?.contacts;
  if (Array.isArray(contacts)) {
    for (const contact of contacts) {
      try {
        await addContact(fp, contact);
      } catch (e) {
        console.warn('[restore] skipped a contact that failed to persist:', (e as Error)?.message);
      }
    }
  }

  await setActiveFingerprint(fp);
  return fp;
}

// ── Check if identity exists (for UI flow) ──────────────────────

export async function hasIdentity(): Promise<boolean> {
  const fp = await getActiveFingerprint();
  if (!fp) return false;
  const identity = await loadIdentity(fp);
  if (!identity) return false;
  // Verify key record exists (don't decrypt — session key may not be set yet)
  const keyRecord = await txGet<any>('keys', fp);
  return keyRecord !== null && keyRecord !== undefined;
}

// ── Clear all data (nuclear option) ─────────────────────────────

export async function clearAll(confirm: 'I understand this deletes all keys'): Promise<void> {
  if (confirm !== 'I understand this deletes all keys') {
    throw new Error('clearAll requires explicit confirmation string');
  }
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const storeNames = Array.from(db.objectStoreNames);
    const tx = db.transaction(storeNames, 'readwrite');
    for (const name of storeNames) {
      tx.objectStore(name).clear();
    }
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

// ── Issued Grow-code tracking (R1 pending-joiner accept-oracle, giver-side) ───
// When a giver mints a Grow invite (createRelay), we remember the shortcode. A
// joiner's SIGNED response binds this code as its inviteNonce (the
// verifyJoinerResponse); the giver's accept-oracle admits the response only if the
// code is one WE issued, still within the ACCEPTANCE WINDOW, under the invite cap,
// and this joiner hasn't already been accepted on it. Layered on the crypto's
// joiner-sig + giverFp-bind + giver-only-decrypt + Invariant-1 defenses. The binding
// is "which invite," not secrecy — the PUBLIC shortcode is fine here.
//
// MULTI-USE: a Grow link accepts up to GROW_INVITE_CAP DISTINCT
// joiners — key the accepted-set by (code, joinerFp), NEVER consume the code.
// Same-joiner replay is dropped here AND idempotent at addContact (fp-dedup).
//
// ACCEPTANCE WINDOW = the mailbox envelope TTL (~7d), NOT the relay's 15-min
// dead-drop: the giver may be offline and poll days later; a legit response must
// still be admitted. Aligns to RELAY_ENVELOPE_TTL_MS default (mailbox-config.ts).
//
// The acceptNonce predicate is SYNC but IndexedDB is async — so the consume
// path loads the map ONCE per poll (loadIssuedCodeMap), builds a sync predicate
// over that snapshot (isCodeOutstanding + codeUnderCap + alreadyAccepted), and
// records accepts back (markAcceptedInMap on the snapshot so later envelopes in the
// same poll see it; recordAcceptedJoiner persists). Codes are per-device, stored in
// the 'settings' k/v store keyed by owner fp so a multi-identity device never crosses
// one issuer's codes into another identity's oracle.

const ISSUED_GROW_CODES_KEY = 'issued_grow_codes';
// Acceptance window matches the mailbox envelope TTL (~7d) so a giver polling days
// after issuing still admits a joiner-response — NOT the 15-min relay dead-drop.
const R1_ACCEPTANCE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** Ceiling for a per-link distinct-joiner cap. */
const ISSUED_CODE_CAP_MAX = 1000;
/** Clamp a per-link cap to an integer in [1, ISSUED_CODE_CAP_MAX]; junk → 1 (single-use, the safe default). */
function clampCodeCap(n: unknown): number {
  const v = Math.floor(Number(n));
  if (!Number.isFinite(v)) return 1;
  return Math.max(1, Math.min(ISSUED_CODE_CAP_MAX, v));
}

/** One issued code: when it stops accepting (epoch ms), which joiner fps it has accepted, and the
 *  per-code distinct-joiner cap (issuer-chosen at generation; default 1 = single-use). */
export interface IssuedCodeEntry { acceptUntil: number; accepted: string[]; cap: number }
/** ownerFp -> { shortcode -> entry } */
export type IssuedCodeMap = Record<string, Record<string, IssuedCodeEntry>>;

function normalizeEntry(e: unknown): IssuedCodeEntry | null {
  if (!e || typeof e !== 'object') return null;
  const r = e as Record<string, unknown>;
  if (!Number.isFinite(r.acceptUntil as number)) return null;
  // cap: a legacy entry (pre-cap) defaults to 1 (single-use) — it must NOT retroactively become
  // multi-use. A present cap is clamped to [1, MAX].
  const cap = r.cap === undefined ? 1 : clampCodeCap(r.cap);
  return { acceptUntil: r.acceptUntil as number, accepted: Array.isArray(r.accepted) ? (r.accepted as string[]) : [], cap };
}

/** Pure: drop entries past their acceptance window. Owners left empty are removed. */
export function pruneIssuedCodes(map: IssuedCodeMap, nowMs: number): IssuedCodeMap {
  const out: IssuedCodeMap = {};
  for (const [fp, codes] of Object.entries(map || {})) {
    const kept: Record<string, IssuedCodeEntry> = {};
    for (const [code, raw] of Object.entries(codes || {})) {
      const entry = normalizeEntry(raw);
      if (entry && entry.acceptUntil > nowMs) kept[code] = entry;
    }
    if (Object.keys(kept).length > 0) out[fp] = kept;
  }
  return out;
}

/** Pure: did this owner issue this code, still within its acceptance window? */
export function isCodeOutstanding(map: IssuedCodeMap, ownerFp: string, code: string, nowMs: number): boolean {
  const e = map?.[ownerFp]?.[code];
  return !!e && Number.isFinite(e.acceptUntil) && e.acceptUntil > nowMs;
}

/** Pure: is this code still under its PER-CODE distinct-joiner cap (stored in the entry, issuer-chosen
 *  at generation; default 1 = single-use)? */
export function codeUnderCap(map: IssuedCodeMap, ownerFp: string, code: string): boolean {
  const e = map?.[ownerFp]?.[code];
  if (!e) return false;
  const cap = Number.isFinite(e.cap) ? e.cap : 1;
  return (Array.isArray(e.accepted) ? e.accepted.length : 0) < cap;
}

/** Pure: has this exact joiner already been accepted on this code? */
export function alreadyAccepted(map: IssuedCodeMap, ownerFp: string, code: string, joinerFp: string): boolean {
  const e = map?.[ownerFp]?.[code];
  return !!e && Array.isArray(e.accepted) && e.accepted.includes(joinerFp);
}

/** Pure: record a VERIFIED joiner fp as accepted on a code (idempotent). Mutates + returns map. */
export function markAcceptedInMap(map: IssuedCodeMap, ownerFp: string, code: string, joinerFp: string): IssuedCodeMap {
  const e = map?.[ownerFp]?.[code];
  if (!e) return map;
  if (!Array.isArray(e.accepted)) e.accepted = [];
  if (!e.accepted.includes(joinerFp)) e.accepted.push(joinerFp);
  return map;
}

async function loadRawIssuedCodeMap(): Promise<IssuedCodeMap> {
  const setting = await txGet<{ key: string; value: string }>('settings', ISSUED_GROW_CODES_KEY);
  if (!setting?.value) return {};
  try {
    const parsed = JSON.parse(setting.value);
    return parsed && typeof parsed === 'object' ? (parsed as IssuedCodeMap) : {};
  } catch {
    return {};
  }
}

async function saveIssuedCodeMap(map: IssuedCodeMap): Promise<void> {
  await txPut('settings', { key: ISSUED_GROW_CODES_KEY, value: JSON.stringify(map) });
}

/**
 * Load the pruned issued-code map for building the SYNC accept-oracle in the consume
 * path. Load ONCE per poll, then pass the snapshot to the pure helpers above.
 */
export async function loadIssuedCodeMap(): Promise<IssuedCodeMap> {
  return pruneIssuedCodes(await loadRawIssuedCodeMap(), Date.now());
}

/** Remember a Grow shortcode this owner just issued, opening a ~7d acceptance window with a per-code
 *  distinct-joiner cap (issuer-chosen at generation; default 1 = single-use, max 1000). */
export async function recordIssuedGrowCode(ownerFp: string, code: string, cap: number = 1): Promise<void> {
  if (!ownerFp || !code) return;
  const map = pruneIssuedCodes(await loadRawIssuedCodeMap(), Date.now());
  if (!map[ownerFp]) map[ownerFp] = {};
  const prior = map[ownerFp][code];
  // Fresh window on (re)issue; preserve any joiners already accepted on this code. The cap is set from
  // the issuer's choice at generation, clamped to [1, 1000].
  map[ownerFp][code] = {
    acceptUntil: Date.now() + R1_ACCEPTANCE_WINDOW_MS,
    accepted: prior?.accepted ?? [],
    cap: clampCodeCap(cap),
  };
  await saveIssuedCodeMap(map);
}

/**
 * Persist a VERIFIED joiner fp as accepted on a code (giver-side, after a non-null
 * verifyJoinerResponse). Records ONLY the crypto-verified fp — never a pre-check claim.
 */
export async function recordAcceptedJoiner(ownerFp: string, code: string, verifiedJoinerFp: string): Promise<void> {
  if (!ownerFp || !code || !verifiedJoinerFp) return;
  const map = pruneIssuedCodes(await loadRawIssuedCodeMap(), Date.now());
  markAcceptedInMap(map, ownerFp, code, verifiedJoinerFp);
  await saveIssuedCodeMap(map);
}

/**
 * Async single-code outstanding check (convenience). The consume path prefers
 * loadIssuedCodeMap + the sync helpers so the accept-oracle stays synchronous.
 */
export async function isOutstandingIssuedCode(ownerFp: string, code: string): Promise<boolean> {
  return isCodeOutstanding(await loadIssuedCodeMap(), ownerFp, code, Date.now());
}
