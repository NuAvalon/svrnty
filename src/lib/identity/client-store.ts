// src/lib/identity/client-store.ts
// Client-side IndexedDB storage for sovereign identity
// Replaces server-side fs operations — all data stays in the user's browser

const DB_NAME = 'svrnty';
const DB_VERSION = 2;

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

interface ContactRecord {
  id: string;
  fingerprint: string;
  name: string;
  email: string;
  public_key: string;
  trust_level: string;
  added_at: string;
  metadata?: any;
  [key: string]: any;
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
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
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

// ── Contact operations ───────────────────────────────────────────

export async function addContact(ownerFingerprint: string, contact: Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'>): Promise<ContactRecord> {
  const id = crypto.randomUUID();
  const record: ContactRecord = {
    ...contact,
    id,
    owner_fingerprint: ownerFingerprint,
    added_at: new Date().toISOString(),
  };
  await txPut('contacts', record);
  return record;
}

export async function updateContact(id: string, updates: Partial<ContactRecord>): Promise<void> {
  const existing = await txGet<ContactRecord>('contacts', id);
  if (!existing) throw new Error('Contact not found');
  await txPut('contacts', { ...existing, ...updates, id: existing.id });
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

  for (const contact of (backup.contacts || [])) {
    await txPut('contacts', { ...contact, owner_fingerprint: fingerprint });
  }

  await setActiveFingerprint(fingerprint);
  return fingerprint;
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
