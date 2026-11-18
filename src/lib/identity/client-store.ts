// src/lib/identity/client-store.ts
// Client-side IndexedDB storage for sovereign identity
// Replaces server-side fs operations — all data stays in the user's browser

// C2 / Invariant-1: the ONE crypto import this storage layer takes —
// a fail-closed fingerprint↔key binding check so no caller can persist a forged contact.
import { fingerprintMatchesKey } from './fingerprint';
import { restoreWritesVerdict, tagRestoreWrites, type OwnerSnapshot } from './restore-writes';
import { canonicalAuthorityPin } from './authority-pin';
import { DEVICE_PASSWORD_MIN } from './device-password';
import { restoreVaultContacts, type VaultContactsReport } from '../contacts/restore-report';
import { keyRecordOpens, restoreDomainDecision, RestoreDomainRefused, type RestoreKeyUse } from './restore-domain';
// Type-only (erased at compile — no runtime import, no cycle): the shape importVaultContents persists.
import type { VaultContents } from '../sync/vault';
// enc-b crypto seam (Flint ◆5701/◆5702, KB#89159): per-contact encryption. deriveContactCryptoKeys
// returns ONLY the two HMAC subkeys {index, manifest}; contact-record AES reuses _sessionKey (below).
import { CONTACT_ENC_VERSION, deriveContactCryptoKeys, encryptContactRecord, decryptContactRecord, blindFingerprint, computeManifestMAC, verifyManifestMAC, type ContactCryptoKeys, type ManifestEntry } from './contact-crypto';
import { isSuppressionRecord, type SuppressionRecord } from '../trust/suppression';
import type { CarriedSuppression } from '../trust/suppression-carry';
import { confirmPendingGlobalOff, makeUpdate, parsePendingGlobalOff, parseRemovedList, recordRemoval, removalRefusal, restoreSuppression, suppressionCarryStatus, suppressionToCarry, type CarryStatus, type ConfirmOutcome, type PendingGlobalOff, type RestorePorts, type RestoreReport, type SealedRead, type Update } from '../trust/suppression-restore';
import { parseDeliveryDefault, restrictOnly, type DeliveryDefault, type DeliveryDefaultRead, type DeliveryDefaultValue } from '../trust/delivery-receipt-setting';
import { isHeldAffirmatives, type HeldAffirmatives } from '../trust/held-affirmatives';
import { isBeaconSeeds, type BeaconSeeds } from './beacon-seeds';
import { isBeaconKeyRecord, newBeaconKeyRecord, type BeaconKeyRecord } from './beacon-key-record';
import { createBeaconStore, createBeaconLatch, beaconRowPrefixes, beaconRowAad, type BeaconKV, type Sealer } from '../trust/beacon-ports';
import { admitContact } from '../trust/admit-contact';
import { relatchFromRecord, repairBlockedButUnsuppressed, BlocksIncompleteError, type RepairOutcome } from '../trust/block-latch';
import { isBeaconConfirmed, withConfirmed, createConfirmedPort, type BeaconConfirmed } from '../trust/beacon-confirmed';
import { beaconPairId } from '../trust/beacon-pair-id';
import type { BeaconStorePort, LatchPort, PairConfirmedPort } from '../crypto/beacon-client';
import { withSafetyWrite } from '@/lib/contacts/safety-write';
import { casUpdateWith, casRetry, sameStoredRow, ContactConflictError, type CasIO, type Expect, type StoredRow } from './contact-cas';
import { ownerHasVerified } from '../trust/trust-recipe';
import { assertFingerprintUnchanged, ContactUpdateRefused } from './contact-identity';
import { DbUpgradeBlocked } from '../db-upgrade-blocked';
// ★★ TRUSTED-DEFINITION CONSISTENCY (#158853): the §G sweep derives "trusted" from the ONE shared
// reveal predicate so sweep ≡ clamp ≡ disable ≡ reveal by construction (edgeTrusted is a pure fn —
// no browser coupling, safe to import here).
import { edgeTrusted } from '../trust/contact-edge';
import { scrubAffirmWireMutual } from '../trust/affirm-wire-purge';
// piece-2 device-mailbox lifecycle: the card-borne receiver keypair (generated once at genesis,
// vault-persisted, secrets never leave the device). mailbox-keys is a leaf crypto util (like the
// fingerprint import above). device-mailbox is PURE helpers (no back-import of this file → no cycle);
// we take only its public-block builder (runtime) + its public-block type (erased).
import {
  generateMailboxKeypair,
  serializeMailboxKeypair,
  deserializeMailboxKeypair,
  toPublicKeys,
  toSecretKeys,
  type MailboxKeypair,
} from '../crypto/mailbox-keys';
import { deriveMailboxFp, type MailboxPublicKeys, type MailboxSecretKeys } from '../crypto/mailbox-envelope';
import { mailboxPublicOf, type DeviceMailboxPublic } from './device-mailbox';
import { backupShardsProblem } from './backup-shards-shape';

const DB_NAME = 'svrnty';
// v4: device_mailbox store (piece-2). One record per identity (keyed by fingerprint), holding the
// vault-encrypted serialized mailbox keypair — the long-lived onion receive keys. Additive: a v3→v4
// upgrade only CREATES the new store (existing stores untouched), and a pre-feature identity lazily
// gets a mailbox on next unlock (ensureDeviceMailboxesOnUnlock).
const DB_VERSION = 4;

// ── Session key management (F1 fix: encrypt keys at rest in IndexedDB) ──
// The session key is a non-extractable CryptoKey held in memory.
// It's derived from the user's passphrase via PBKDF2 (600K iterations SHA-256).
// Lost on tab close/refresh — user must re-enter passphrase to unlock.

let _sessionKey: CryptoKey | null = null;
let _sessionSalt: Uint8Array | null = null;
// enc-b HMAC subkeys: index = blinded-fp keyed-PRF; manifest = book-integrity MAC. Derived at
// initSessionKey (from the passphrase + salt-b), cleared on lock. Contact AES reuses _sessionKey.
let _contactKeys: ContactCryptoKeys | null = null;

// ── session-lock hooks (P1#1 cross-identity notes-leak fix, Flint co-verify #169668) ─────────
// Session-scoped keys held OUTSIDE this module — notably the notes store's passphrase-derived
// _notesKey — must be dropped whenever the session LOCKS or the active identity SWITCHES, else B
// inherits A's still-loaded key and reads A's plaintext notes. The holder REGISTERS inward
// (messaging → client-store) so identity-core never imports a feature module (that direction caused
// a tsc cycle). Fired from BOTH lockSession AND setActiveFingerprint — the latter is the TRUE
// universal switch chokepoint (menu-switch, restore, AND import-activation route through it;
// lockSession alone misses restore + import).
const _sessionLockHooks: Array<() => void> = [];
export function onSessionLock(fn: () => void): void {
  _sessionLockHooks.push(fn);
}
function fireSessionLockHooks(): void {
  for (const h of _sessionLockHooks) {
    try { h(); } catch { /* a hook must never block the lock/switch */ }
  }
}

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
 * enc-b HMAC-master salt = option (b), Flint-locked: SHA-256('svrnty/enc-b/hmac-master-salt/v1' ‖
 * key_encryption_salt). Distinct from key_encryption_salt (domain separation between the AES
 * _sessionKey and the HMAC-master), inherits its per-install randomness, no new stored state.
 */
async function deriveHmacMasterSalt(keSalt: Uint8Array): Promise<Uint8Array> {
  const label = new TextEncoder().encode('svrnty/enc-b/hmac-master-salt/v1');
  const preimage = new Uint8Array(label.length + keSalt.length);
  preimage.set(label, 0);
  preimage.set(keSalt, label.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', preimage));
}

/**
 * Initialize the session key from a user passphrase.
 * Call once per session (on identity creation or unlock).
 * The derived CryptoKey is held in memory — lost on tab close.
 */
export async function initSessionKey(passphrase: string): Promise<void> {
  // First, before the key changes: the old verified set must never meet a new, unverified key.
  _unlockVerifiedOwners = new Set();
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
  // enc-b: derive the two HMAC subkeys {index, manifest} from the passphrase via the salt-(b)
  // HMAC-master. Contact-record AES reuses _sessionKey (◆5701) — no separate AES key derived here.
  _contactKeys = await deriveContactCryptoKeys(passphrase, await deriveHmacMasterSalt(salt), PBKDF2_ITERATIONS);
  // Before any migration below: decides which owners those migrations may touch.
  _unlockVerifiedOwners = await ownersVerifiedBySession();
  // enc-b B5: on every unlock, heal any legacy plaintext-at-rest contacts to encrypted, then establish
  // (first run / post-upgrade) or verify the per-owner book manifest. Best-effort + resumable — it
  // never throws into the unlock path (a hiccup just leaves work for next unlock; a manifest MISMATCH
  // sets a corrupt flag for the recovery UI rather than raising).
  await migrateAndVerifyContactsOnUnlock();
  // piece-1 #111-legacy sweep (Archie do-no-harm #158835): clear open_visibility on every NON-trusted
  // contact so B1's `&& e.trusted` drop has zero transitional-reveal. Must run WITH the mask-drop. Best-effort.
  await migratePerContactPrivacyOnUnlock();
  // #593 affirm-wire removal: one-time idempotent PURGE of the device-held mutual-trust taint written by
  // the removed affirm-wire (mutual.{they_trust_me,reciprocal,last_affirm_at}). Best-effort, logged.
  await purgeAffirmWireMutualTaintOnUnlock();
  // enc-b Blocker-C (eager half): proactively heal plaintext-fallback identity-store records (keys/
  // pq_keys/vaults/shards) so never-read-post-unlock stragglers (esp. shards) don't sit plaintext.
  await eagerMigrateIdentityStoresOnUnlock();
  // piece-2: lazily ensure every identity has a device mailbox (heals pre-v4 identities). Best-effort,
  // never throws into unlock; regenerates only on genuine absence, never on a decrypt-fail (see fn).
  await ensureDeviceMailboxesOnUnlock();
  // Complete a Block whose record write did not finish, and latch every person the record or the removed list names that has no latch yet (a crash between a restore and its
  // rebuild leaves exactly that). Best-effort, never throws into unlock.
  await repairBlocksOnUnlock();
}

/**
 * Owners whose existing encrypted records open under the current session key. initSessionKey doesn't validate the passphrase, so this
 * is what stands between a mistyped passphrase and a write: anything that heals plaintext or creates a record at unlock runs only for
 * these owners. An owner with no encrypted rows can't be verified and stays as it was; a key lost under a typo can't be recovered.
 */
let _unlockVerifiedOwners: Set<string> = new Set();

const OWNER_KEY_STORES = ['keys', 'pq_keys', 'vaults', 'shards', 'device_mailbox'];
const MAX_CONTACT_SAMPLES = 3;

async function sessionVerifiesOwner(owner: string, contactRows: Array<Record<string, unknown>>): Promise<boolean> {
  if (!_sessionKey) return false;
  for (const store of OWNER_KEY_STORES) {
    if (await keyRecordOpens(await txGet<unknown>(store, owner), _sessionKey, ENC_VERSION)) return true;
  }
  for (const rec of contactRows.filter((r) => r.enc_version && typeof r.ciphertext === 'string').slice(0, MAX_CONTACT_SAMPLES)) {
    try {
      await decryptContactIfNeeded(rec);
      return true;
    } catch {
      /* wrong key for this row: try the next sample */
    }
  }
  return false;
}

/** Reads only, and never throws into unlock: any failure means nobody is verified, so nothing is written. */
async function ownersVerifiedBySession(): Promise<Set<string>> {
  const verified = new Set<string>();
  try {
    const contacts = await txGetAll<Record<string, unknown>>('contacts');
    const owners = new Set<string>((await listIdentities()).map((i) => i.fingerprint));
    for (const c of contacts) if (typeof c?.owner_fingerprint === 'string') owners.add(c.owner_fingerprint);
    for (const owner of owners) {
      if (await sessionVerifiesOwner(owner, contacts.filter((c) => c?.owner_fingerprint === owner))) verified.add(owner);
    }
    const unverified = owners.size - verified.size;
    if (unverified > 0) console.info(`[enc-b] ${unverified} owner(s) could not be verified on this unlock; left as they were`);
  } catch {
    verified.clear();
  }
  return verified;
}

/** Check if the session is unlocked (key available in memory). */
export function isSessionUnlocked(): boolean {
  return _sessionKey !== null;
}

/** Lock the session — clear the key from memory. */
export function lockSession(): void {
  _sessionKey = null;
  _sessionSalt = null;
  _contactKeys = null;
  _unlockVerifiedOwners = new Set();
  fireSessionLockHooks(); // P1#1: drop the notes-store key (+ any registered session-scoped key) on lock
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
  // ── delivery receipts (task #714 R2a): this contact's override of the global default, read AT SEND. Absent = follow the global. ──
  delivery_receipts?: 'on' | 'off';
  // ── piece-2 device-mailbox (onion seal-target) ──────────────────────────────
  // The peer's PUBLIC device-mailbox block (fp + x25519/ml-kem pubkeys, hex). Stored ONLY from a card
  // whose signature VERIFIED (classifyImportedCard branch 4) — a seal-target is as MITM-sensitive as
  // pq_kem, so a no/invalid-signature card drops it (emit under-reveals). Read via peerDeviceMailbox().
  device_mailbox?: DeviceMailboxPublic;
  // ── #787 the contact's authority pin ────────────────────────────────────────────────────────────────────────────────
  // The 64-hex next_authority_commitment the contact's signed card carried at import. Stored ONLY from a card whose signature VERIFIED
  // (classifyImportedCard branch 4), and FIRST WRITE WINS: a later card with a different pin never replaces it (the import raises the loud
  // alarm instead). Nothing reads it yet: it is kept so a later relay move or key rotation can be checked against it.
  next_authority_commitment?: string;
  // ── the contact's beacon key (mutual-trust wire, DARK) ──────────────────────────────────────
  // The contact's beacon PUBLIC key and its generation, from a card whose signature VERIFIED (classifyImportedCard branch 4, which also checks the key and
  // the generation rules). Stored for every contact whatever their trust level: a stored key enables nothing by itself. A held key is never replaced at
  // intake (a newer generation waits for the release-first path); see beacon-contact-key.ts. Carried ONLY by the encrypted backup: it is on no contact-book
  // export allowlist, plain or sealed.
  beacon_public_key?: string;
  beacon_key_generation?: number;
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
      // v4: device_mailbox — MY long-lived onion receive keypair (one per identity, keyed by
      // fingerprint). The serialized keypair is key material → encrypted at rest like the vault
      // (storeDeviceMailbox is Blocker-C fail-closed). Public keys + content-fp are published via the
      // SIGNED identity card, never a relay index (/mailbox/register stays unwired — blind-binding gate).
      if (!db.objectStoreNames.contains('device_mailbox')) {
        db.createObjectStore('device_mailbox', { keyPath: 'fingerprint' });
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
    request.onblocked = () => reject(new DbUpgradeBlocked());
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

/** Put `value` under `key` ONLY IF no row exists, in one readwrite transaction (no await between the get and the put). Returns whether it wrote. */
async function txPutIfAbsent(storeName: string, key: string, value: unknown): Promise<boolean> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const os = tx.objectStore(storeName);
    let wrote = false;
    const existing = os.get(key);
    existing.onsuccess = () => {
      if (existing.result === undefined) {
        os.put(value);
        wrote = true;
      }
    };
    tx.oncomplete = () => resolve(wrote);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/** Atomic create-if-absent: a single readwrite transaction whose `add` fails with ConstraintError if the key exists. Resolves 'exists' for that case
 * (never overwrites), rejects on any other failure. Two tabs racing to create the same record: exactly one 'added'. */
async function txAdd<T>(storeName: string, value: T): Promise<'added' | 'exists'> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    let exists = false;
    const req = store.add(value);
    req.onerror = (ev) => {
      if (req.error && req.error.name === 'ConstraintError') { exists = true; ev.preventDefault(); ev.stopPropagation(); }
    };
    tx.oncomplete = () => { db.close(); resolve(exists ? 'exists' : 'added'); };
    tx.onabort = () => { db.close(); reject(tx.error ?? new Error('transaction aborted')); };
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

// Multi-store atomic write (enc-b B4): put/delete across several stores in ONE IndexedDB transaction,
// so a contact record and its book-manifest (or a delete and the manifest) commit together or not at
// all. FOOTGUN (why this helper exists): an IDB txn auto-commits as soon as the microtask queue drains
// with no pending IDB request — so callers must compute the manifest MAC + gather all entries BEFORE
// calling this; the body here does synchronous puts/deletes only, never an awaited non-IDB op mid-tx.
type TxOp = { store: string; value: unknown } | { store: string; delete: string };

async function txPutMany(ops: TxOp[]): Promise<void> {
  const db = await openDB();
  const stores = [...new Set(ops.map((o) => o.store))];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(stores, 'readwrite');
    let firstError: unknown = null;
    for (const op of ops) {
      const store = tx.objectStore(op.store);
      const req = 'delete' in op ? store.delete(op.delete) : store.put(op.value);
      req.onerror = () => { firstError = firstError ?? req.error; }; // capture the FIRST error (e.g. ConstraintError) before the abort; later requests report AbortError
    }
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onabort = () => { db.close(); reject(firstError ?? tx.error ?? new Error('transaction aborted')); };
    tx.onerror = () => { db.close(); reject(firstError ?? tx.error ?? new Error('transaction error')); };
  });
}

// ── Identity operations ──────────────────────────────────────────

export async function storeIdentity(fingerprint: string, data: any): Promise<void> {
  // A record already here keeps its created_at when the data carries none, so writing the same identity again leaves the same row.
  const existing = data.created_at ? null : await txGet<IdentityRecord>('identities', fingerprint);
  await txPut('identities', {
    fingerprint,
    data,
    created_at: data.created_at || existing?.created_at || new Date().toISOString(),
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
  // P1#1: EVERY identity switch routes through here (menu-switch, restore, import-activation) — drop the
  // prior identity's session-scoped keys (the notes-store _notesKey) FIRST so B never inherits A's loaded
  // key and reads A's plaintext. This is the TRUE switch chokepoint (lockSession alone misses restore + import).
  fireSessionLockHooks();
  await txPut('settings', { key: 'active_fingerprint', value: fingerprint });
}

// ── Piece-2 mutual-block: durable owner-local SUPPRESSION record (§F2/§F3, spec KB#92246) ──────────
// F's emit-side "whom I've gone private to" set {global, groups, persons(durable_id)} (suppression.ts).
// Encrypted at rest via the SAME AAD-bound contact-crypto path, domain-separated by a RESERVED id — so a
// suppression blob can't be transplanted onto a contact row or another owner (the GCM tag binds id+owner).
// Owner-local, NEVER on the wire (§C firewall). person entries are rotation-stable durable_ids → the set
// survives key-rotation / mailbox-rebuild / relay-transfer (it's F's vault data, not key-derived).
const SUPPRESSION_RECORD_ID = 'piece2:suppression'; // reserved AAD id (contacts use random UUIDs — never this)
function suppressionSettingKey(ownerFingerprint: string): string {
  return `suppression:${ownerFingerprint}`;
}

/**
 * Read F's durable suppression record. ★ FAIL-CLOSED (§F3): returns null on ANY doubt — session locked,
 * record ABSENT, decrypt/tag failure, or a malformed/legacy shape. The emit path treats null as SUPPRESS-ALL
 * (emit to no one) — we never un-suppress a survivor because the store couldn't be read. A genuinely
 * never-suppressed user is made discoverable by an EXPLICIT empty record (setSuppressionRecord, written at
 * unlock/genesis — emit-path integration), NOT by this returning an empty set on absence.
 */
export async function getSuppressionRecord(ownerFingerprint: string): Promise<SuppressionRecord | null> {
  if (!_sessionKey) return null; // locked ⇒ fail-closed
  try {
    const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>(
      'settings', suppressionSettingKey(ownerFingerprint),
    );
    if (!row?.value) return null; // absent ⇒ fail-closed (the store can't tell never-had from lost)
    const rec = await decryptContactRecord<unknown>(_sessionKey, SUPPRESSION_RECORD_ID, ownerFingerprint, row.value);
    return isSuppressionRecord(rec) ? rec : null; // malformed ⇒ fail-closed
  } catch {
    return null; // decrypt/tag failure ⇒ fail-closed
  }
}

/** Persist F's suppression record, encrypted at rest (fail-closed: throws if locked — never write plaintext). */
export async function setSuppressionRecord(ownerFingerprint: string, rec: SuppressionRecord): Promise<void> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store suppression record unencrypted (§C/enc-b fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, SUPPRESSION_RECORD_ID, ownerFingerprint, rec);
  await txPut('settings', { key: suppressionSettingKey(ownerFingerprint), value: payload });
}

// ── Restoring the owner's suppression: two more sealed records, and the export, restore, record-a-Remove and confirm entry points ──────────────────────
// The logic is in ../trust/suppression-restore.ts (pure, tested over in-memory ports); this is the storage under it. Two records, the same pattern as above (the `settings` store,
// encryptContactRecord under a reserved AAD id, the owner as authenticated data), both listed in OWNER_SEALED_SETTINGS:
//  - the REMOVED list: durable ids of contacts the owner removed. A Remove deletes the contact and its latch row keeps only a one-way pair id, so without this list nothing could rebuild a
//    latch after a restore. Only Removes recorded AFTER it exists are in it; an earlier one cannot be recovered.
//  - the PENDING marker: left by a restore onto a device with no suppression record when the backup said global off; the person's confirmation consumes it.
// A carried record is read ONLY from the passphrase-authenticated vault (importVaultContentsReport), never from a plaintext file, and exportAll never carries it.
// EVERY change to the suppression record or the removed list is ONE compare-and-swap (updateSealed): read the stored row, decide on it, and commit only if the row is still exactly what was
// read, else decide again. Never read-then-replace: a write that lands in between (a second tab, a Remove) would be overwritten by the stale result, and that loosens.
const REMOVED_RECORD_ID = 'piece2:removed'; // reserved AAD id
function removedSettingKey(ownerFingerprint: string): string {
  return `removed_contacts:${ownerFingerprint}`;
}
const SUPPRESSION_PENDING_RECORD_ID = 'piece2:suppression-pending'; // reserved AAD id
function suppressionPendingSettingKey(ownerFingerprint: string): string {
  return `suppression_pending:${ownerFingerprint}`;
}

export type SealedRow = { key: string; value: { iv: string; ciphertext: string; enc_version?: number } };

/** A stored settings row as ok / absent / unreadable (locked, a decrypt or tag failure, or a shape its strict parser refuses). A row that cannot be read is never taken for "absent". */
async function decodeSealed<T>(row: SealedRow | null, ownerFingerprint: string, recordId: string, parse: (x: unknown) => T | null): Promise<SealedRead<T>> {
  if (!_sessionKey) return { state: 'unreadable' };
  try {
    if (!row?.value) return { state: 'absent' };
    const parsed = parse(await decryptContactRecord<unknown>(_sessionKey, recordId, ownerFingerprint, row.value));
    return parsed === null ? { state: 'unreadable' } : { state: 'ok', value: parsed };
  } catch {
    return { state: 'unreadable' };
  }
}

async function readSealed<T>(ownerFingerprint: string, settingKey: string, recordId: string, parse: (x: unknown) => T | null): Promise<SealedRead<T>> {
  try {
    return await decodeSealed(await txGet<SealedRow>('settings', settingKey), ownerFingerprint, recordId, parse);
  } catch {
    return { state: 'unreadable' };
  }
}

export const readRemovedList = (ownerFingerprint: string): Promise<SealedRead<string[]>> =>
  readSealed(ownerFingerprint, removedSettingKey(ownerFingerprint), REMOVED_RECORD_ID, parseRemovedList);
export const readPendingGlobalOff = (ownerFingerprint: string): Promise<SealedRead<PendingGlobalOff>> =>
  readSealed(ownerFingerprint, suppressionPendingSettingKey(ownerFingerprint), SUPPRESSION_PENDING_RECORD_ID, parsePendingGlobalOff);

// One seal function per record, each with its own direct call, so the sealed-record list test can see which reserved id every write uses.
async function sealSuppression(ownerFingerprint: string, rec: SuppressionRecord): Promise<unknown> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store suppression record unencrypted (§C/enc-b fail-closed)');
  return encryptContactRecord(_sessionKey, SUPPRESSION_RECORD_ID, ownerFingerprint, rec);
}
async function sealRemoved(ownerFingerprint: string, list: string[]): Promise<unknown> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store the removed list unencrypted (fail-closed)');
  return encryptContactRecord(_sessionKey, REMOVED_RECORD_ID, ownerFingerprint, list);
}

export interface SealedRowDeps<T> {
  settingKey: string;
  readRow(): Promise<SealedRow | null>;
  openDb(): Promise<IDBDatabase>;
  decode(row: SealedRow | null): Promise<SealedRead<T>>;
  seal(value: T): Promise<unknown>;
}

/**
 * The storage under the atomic update (makeUpdate, in ../trust/suppression-restore.ts, is the loop): `read` returns the stored row as the token and its decoded state; `commit` seals the new
 * value and writes it only if the row is STILL exactly the token (commitIfUnchanged: the compare and the write are one transaction, the same commit the contact writes use). A row that could
 * not be read is never overwritten (makeUpdate refuses a write decided on it). The dependencies are injected so the glue can be tested against a fake database.
 */
export function sealedRowUpdate<T>(deps: SealedRowDeps<T>): Update<T> {
  return makeUpdate<T>({
    read: async () => {
      const row = await deps.readRow();
      return { token: row, held: await deps.decode(row) };
    },
    commit: async (token, value) => {
      const payload = await deps.seal(value);
      return commitIfUnchanged(await deps.openDb(), [{ store: 'settings', key: deps.settingKey, expected: token as StoredRow }], [{ store: 'settings', value: { key: deps.settingKey, value: payload } }]);
    },
  });
}

function updateSealed<T>(ownerFingerprint: string, settingKey: string, recordId: string, parse: (x: unknown) => T | null, seal: (value: T) => Promise<unknown>): Update<T> {
  return sealedRowUpdate<T>({
    settingKey,
    readRow: () => txGet<SealedRow>('settings', settingKey),
    openDb: openDB,
    decode: (row) => decodeSealed(row, ownerFingerprint, recordId, parse),
    seal,
  });
}

async function writePendingGlobalOff(ownerFingerprint: string, marker: PendingGlobalOff): Promise<void> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store the restore marker unencrypted (fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, SUPPRESSION_PENDING_RECORD_ID, ownerFingerprint, marker);
  await txPut('settings', { key: suppressionPendingSettingKey(ownerFingerprint), value: payload });
}

async function clearPendingGlobalOff(ownerFingerprint: string): Promise<void> {
  await txDelete('settings', suppressionPendingSettingKey(ownerFingerprint));
}

/**
 * The ONE atomic update of the owner's suppression record. The restore and the Block / Unblock actions all change the record through it, never by read-then-replace: a write that lands
 * between a read and a commit (a second tab, a restore) is kept, because the commit only happens if the record is still what was read.
 */
export const updateSuppressionRecord = (ownerFingerprint: string): Update<SuppressionRecord> =>
  updateSealed<SuppressionRecord>(ownerFingerprint, suppressionSettingKey(ownerFingerprint), SUPPRESSION_RECORD_ID, (x) => (isSuppressionRecord(x) ? x : null), (v) => sealSuppression(ownerFingerprint, v));

function createRestorePorts(ownerFingerprint: string): RestorePorts {
  return {
    updateSuppression: updateSuppressionRecord(ownerFingerprint),
    updateRemoved: updateSealed<string[]>(ownerFingerprint, removedSettingKey(ownerFingerprint), REMOVED_RECORD_ID, parseRemovedList, (v) => sealRemoved(ownerFingerprint, v)),
    readPending: () => readPendingGlobalOff(ownerFingerprint),
    writePending: (marker) => writePendingGlobalOff(ownerFingerprint, marker),
    clearPending: () => clearPendingGlobalOff(ownerFingerprint),
  };
}

/**
 * The export side, for the SEALED vault only (VaultExportDialog). All or nothing: an unreadable record or an unreadable removed list is not carried (undefined), and so is anything the strict
 * parser would refuse. exportAll never calls this: the plaintext export must not be able to carry a list of people someone removed.
 */
export async function exportSuppressionCarry(ownerFingerprint: string): Promise<CarriedSuppression | undefined> {
  return suppressionToCarry(await getSuppressionRecord(ownerFingerprint), await readRemovedList(ownerFingerprint));
}

/**
 * Whether the sealed vault will carry the owner's blocks, for the export screen to say so BEFORE the file is saved. Unlike exportSuppressionCarry it tells "nothing to carry" (never blocked or removed
 * anyone) from "left out" (an unreadable record or list, a list over the cap): only the second needs a notice. A locked session reads as unreadable, so it is left out.
 */
export async function readSuppressionCarryStatus(ownerFingerprint: string): Promise<CarryStatus> {
  const record = await readSealed<SuppressionRecord>(ownerFingerprint, suppressionSettingKey(ownerFingerprint), SUPPRESSION_RECORD_ID, (x) => (isSuppressionRecord(x) ? x : null));
  return suppressionCarryStatus(record, await readRemovedList(ownerFingerprint));
}

/**
 * The restore side: apply what the passphrase-authenticated vault carried (anything: it is parsed strictly). Best-effort, because a failure leaves the device as dark as it was, which is the safe
 * state, and a restore must not fail over it. Null means it threw.
 */
export async function restoreCarriedSuppression(ownerFingerprint: string, carried: unknown, backupAt: unknown): Promise<RestoreReport | null> {
  try {
    return await restoreSuppression(carried, { backupAt, restoredAt: new Date().toISOString() }, createRestorePorts(ownerFingerprint));
  } catch (e) {
    console.warn('[restore] suppression record not applied (the device stays private)', e);
    return null;
  }
}

/**
 * Record one Remove. It THROWS when it cannot be recorded (an unreadable list, a full list, a malformed id), so the caller's Remove fails and writes no latch: a Remove that leaves no durable id is
 * the loss this list exists to stop. NOT CALLED YET: no Remove path reaches the beacon latch today, so whoever wires one must call this FIRST, before the latch write.
 */
export async function recordRemovedContact(ownerFingerprint: string, durableId: string): Promise<void> {
  const refusal = removalRefusal(await recordRemoval(createRestorePorts(ownerFingerprint).updateRemoved, durableId));
  if (refusal !== null) throw new Error(refusal);
}

// ── Block and Remove set the beacon latch; the suppression record and the latches are repaired at unlock and before every export ─────────────────────────────────
// DARK: nothing here sends a request. `blockLatchPortsFor` is the ONE place a screen gets the latch from. It writes the same LOCAL latch createBeaconWire writes while the wire is OFF
// (beacon-wire.ts, removeAtTap). When the beacon client gets its first importer, THIS is what moves to wire.client.removeAtTap (a go-live gate), so Block and Remove also withdraw.

/** What a Block / Remove screen needs: the pair id of a contact (the unlocked session) and this owner's latch. */
export function blockLatchPortsFor(ownerFingerprint: string): { pairIdFor: (durableId: string) => Promise<string>; latch: LatchPort } {
  return { pairIdFor: beaconPairIdFor, latch: createBeaconPorts(ownerFingerprint).latch };
}

/** Each contact's durable id and whether it is BLOCKED, by the same rule admitContact applies everywhere else (the blocked flag, top level or in metadata). */
async function blockedContactsOf(ownerFingerprint: string): Promise<Array<{ durableId: string; blocked: boolean }>> {
  return (await getAllContacts(ownerFingerprint)).map((c) => ({ durableId: String((c as { fingerprint?: unknown }).fingerprint ?? ''), blocked: !admitContact(c) }));
}

/**
 * Forward repair: a contact whose blocked flag is set but who is not in the suppression record is added to it (atomic, adds only, never writes an unreadable or absent record).
 * Runs at unlock and BEFORE every sealed export; 'error' means the repair write itself failed, and the export must REFUSE.
 */
export async function repairSuppressionRecord(ownerFingerprint: string): Promise<RepairOutcome> {
  return (await repairBlockedButUnsuppressed({ contacts: () => blockedContactsOf(ownerFingerprint), updateSuppression: updateSuppressionRecord(ownerFingerprint) })).outcome;
}

/** The export's gate: the forward repair, and the export REFUSES (throws) when the repair write itself failed. An unreadable or absent record is not a refusal here (the left-out notice covers it). */
export async function repairSuppressionOrRefuse(ownerFingerprint: string): Promise<void> {
  if ((await repairSuppressionRecord(ownerFingerprint)) === 'error') throw new BlocksIncompleteError();
}

/** Reverse pass: every person in the suppression record and every removed id that has no latch gets one (tighten only). Counts only. */
export async function relatchBlocksForOwner(ownerFingerprint: string): ReturnType<typeof relatchFromRecord> {
  const { pairIdFor, latch } = blockLatchPortsFor(ownerFingerprint);
  return relatchFromRecord({
    readPersons: async () => (await getSuppressionRecord(ownerFingerprint))?.persons ?? null,
    readRemoved: async () => {
      const r = await readRemovedList(ownerFingerprint);
      return r.state === 'ok' ? r.value : r.state === 'absent' ? [] : null;
    },
    readBookIds: async () => (await getAllContacts(ownerFingerprint)).map((x) => String((x as { fingerprint?: unknown }).fingerprint ?? '')).filter(Boolean),
    pairIdFor,
    latch,
  });
}

/** At unlock, for every owner this session verifies: the forward repair, then the reverse pass. Best effort, never throws into unlock; the log carries counts only, never an id. */
async function repairBlocksOnUnlock(): Promise<void> {
  for (const owner of _unlockVerifiedOwners) {
    try {
      const record = await repairSuppressionRecord(owner).catch(() => 'error' as const);
      const latches = await relatchBlocksForOwner(owner);
      console.info(`[beacon-latch] unlock repair: record ${record}; latches ${latches.outcome} (${latches.latched} set, ${latches.failed} failed)`);
    } catch {
      console.warn('[beacon-latch] unlock repair did not finish; the device stays as private as it was');
    }
  }
}

/** The person's confirmation after a restore: switch global OFF. Needs the marker a restore left; see confirmPendingGlobalOff. */
export const confirmGlobalOffAfterRestore = (ownerFingerprint: string): Promise<ConfirmOutcome> => confirmPendingGlobalOff(createRestorePorts(ownerFingerprint));

// ── Piece-2 mutual-block: VIEWER-SIDE held-affirmatives store ──────────────────────────────────────
// Anna's received+verified affirmatives {signer durable_id → {validUntil,epoch}} (held-affirmatives.ts).
// The reveal AND-gate (trust map) READS this; the receive-path (next layer, over Athena's /onion transport)
// WRITES it. Encrypted at rest via the same AAD-bound path (reserved domain id). Owner-local; derived from
// wire-received payloads but never re-serialized outbound.
const HELD_AFFIRMS_RECORD_ID = 'piece2:held-affirms'; // reserved AAD id
function heldAffirmsSettingKey(ownerFingerprint: string): string {
  return `held_affirms:${ownerFingerprint}`;
}

/**
 * Read Anna's held-affirmatives map. ★ FAIL-CLOSED (§F3): null on ANY doubt (locked / absent / decrypt-fail
 * / malformed). The reveal gate treats null as "surface nothing transitive" (affirmGateCircle(_, null, _) =
 * []) — under-reveal, never surface on a guess. Absent is simply "no affirmatives held yet" → the gate
 * surfaces nothing, which is the correct DARK-until-receive state; returning null here is equivalent for the
 * gate (both ⇒ surface nothing), so absent→null is safe (unlike suppression, where absent vs empty differs).
 */
export async function getHeldAffirmatives(ownerFingerprint: string): Promise<HeldAffirmatives | null> {
  if (!_sessionKey) return null;
  try {
    const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>(
      'settings', heldAffirmsSettingKey(ownerFingerprint),
    );
    if (!row?.value) return null;
    const map = await decryptContactRecord<unknown>(_sessionKey, HELD_AFFIRMS_RECORD_ID, ownerFingerprint, row.value);
    return isHeldAffirmatives(map) ? map : null;
  } catch {
    return null;
  }
}

/** Persist Anna's held-affirmatives map, encrypted at rest (fail-closed: throws if locked). Receive-path only. */
export async function setHeldAffirmatives(ownerFingerprint: string, map: HeldAffirmatives): Promise<void> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store held-affirmatives unencrypted (§C/enc-b fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, HELD_AFFIRMS_RECORD_ID, ownerFingerprint, map);
  await txPut('settings', { key: heldAffirmsSettingKey(ownerFingerprint), value: payload });
}

// ── Delivery-receipt setting (task #714 R2a): the GLOBAL default, a sealed per-owner record ───────────────────────
// Same pattern as the suppression and held-affirmatives records: the `settings` store, encryptContactRecord under a reserved AAD id, so the
// blob cannot be moved onto a contact row or another owner. Not the identity row (plaintext at rest) and not localStorage (no owner scope, and
// clearing site data would silently turn Off back into On).
const DELIVERY_RECORD_ID = 'piece2:delivery-receipts'; // reserved AAD id (contacts use random UUIDs, never this)
function deliverySettingKey(ownerFingerprint: string): string {
  return `delivery_receipts:${ownerFingerprint}`;
}

/** Read the record. ★ FAIL-CLOSED: locked, a decrypt/tag failure or a malformed shape is 'unreadable' (the caller sends nothing); no row is 'absent'. */
export async function readDeliveryDefault(ownerFingerprint: string): Promise<DeliveryDefaultRead> {
  if (!_sessionKey) return { state: 'unreadable' };
  try {
    const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>('settings', deliverySettingKey(ownerFingerprint));
    if (!row?.value) return { state: 'absent' };
    return parseDeliveryDefault(await decryptContactRecord<unknown>(_sessionKey, DELIVERY_RECORD_ID, ownerFingerprint, row.value));
  } catch {
    return { state: 'unreadable' };
  }
}

/** Replace the record (the owner's own choice, or answering the one-time question). Throws when locked: never stored unencrypted. */
export async function writeDeliveryDefault(ownerFingerprint: string, rec: DeliveryDefault): Promise<void> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store the delivery-receipt setting unencrypted (fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, DELIVERY_RECORD_ID, ownerFingerprint, rec);
  await txPut('settings', { key: deliverySettingKey(ownerFingerprint), value: payload });
}

/**
 * Write `rec` only if NO record exists yet. Used by restores (which mark 'unknown') and by the migration below, so a late migration can never
 * overwrite a marker or an answer. Returns whether it wrote.
 */
export async function writeDeliveryDefaultIfAbsent(ownerFingerprint: string, rec: DeliveryDefault): Promise<boolean> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store the delivery-receipt setting unencrypted (fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, DELIVERY_RECORD_ID, ownerFingerprint, rec);
  return txPutIfAbsent('settings', deliverySettingKey(ownerFingerprint), { key: deliverySettingKey(ownerFingerprint), value: payload });
}

/**
 * The read a SEND uses. An ABSENT record here is an identity that existed before this setting did (a restore marks 'unknown' first), and prod
 * already sends receipts for it, so it is switched to 'on' ONCE and flagged for a one-time notice. Written only-if-absent, then read back, so a
 * concurrent writer wins. Anything unreadable stays unreadable.
 */
export async function readDeliveryDefaultMigrating(ownerFingerprint: string): Promise<DeliveryDefaultRead> {
  const first = await readDeliveryDefault(ownerFingerprint);
  if (first.state !== 'absent') return first;
  try {
    // A restore path that could not seal a marker (no session yet) left the plaintext flag: that identity was restored here, so its choice is unknown.
    const restored = await txGet<{ key: string; value: string }>('settings', deliveryRestoredFlagKey(ownerFingerprint));
    await writeDeliveryDefaultIfAbsent(ownerFingerprint, restored ? { v: 1, value: 'unknown' } : { v: 1, value: 'on', notice_pending: true });
    if (restored) await txDelete('settings', deliveryRestoredFlagKey(ownerFingerprint)).catch(() => {});
  } catch {
    return { state: 'unreadable' };
  }
  return readDeliveryDefault(ownerFingerprint);
}

function deliveryRestoredFlagKey(ownerFingerprint: string): string {
  return `delivery_receipts_restored:${ownerFingerprint}`;
}

/**
 * For a restore path that has NO session key to seal with: leave a plaintext flag ("this identity was restored on this device", nothing
 * secret in it). The first send's migration reads it and records 'unknown' instead of 'on'. Never throws on a locked session.
 */
export async function markDeliveryRestored(ownerFingerprint: string): Promise<void> {
  await txPut('settings', { key: deliveryRestoredFlagKey(ownerFingerprint), value: '1' });
}

/** A restore's marker: the choice is not known on this device, so the owner is asked once and nothing is sent until they answer. */
export async function markDeliveryDefaultUnknown(ownerFingerprint: string): Promise<void> {
  await writeDeliveryDefaultIfAbsent(ownerFingerprint, { v: 1, value: 'unknown' });
}

// ── Lenses v1.3: the SEALED recipient→lens grant book (contract review-1 item 6) ────────────────
// The grant book is the owner's contact fingerprints + which face each person gets + what each was
// sent — a ranking of their relationships. It must be sealed at rest: the same AAD-bound
// contact-crypto path, a reserved domain id, the `settings` store (which exportAll never reads).
// Owner-local, NEVER on the wire. Stated bound: an unlocked phone shows all of it.
const LENS_BOOK_RECORD_ID = 'lenses:grant-book'; // reserved AAD id (contacts use random UUIDs, never this)
function lensBookSettingKey(ownerFingerprint: string): string {
  return `lens_book:${ownerFingerprint}`;
}

/**
 * Read the serialized grant book. ABSENT vs UNREADABLE are different verdicts (lenses R2a / at-rest
 * A4): only a genuinely ABSENT record reads as null (the caller treats that as an empty book —
 * zero methods go, updates hold — which is exactly the "no record" rule). A locked session, a
 * decrypt/tag failure (a wrong passphrase reads as one), a non-string payload and a store error
 * all THROW — the caller marks the book unreadable and read-only, so a transient fault can never
 * stand in as an empty book that a later save would overwrite.
 */
export async function readLensGrantBook(ownerFingerprint: string): Promise<string | null> {
  if (!_sessionKey) throw new Error('lens grant book unreadable: session locked');
  const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>(
    'settings', lensBookSettingKey(ownerFingerprint),
  );
  if (!row?.value) return null;
  const rec = await decryptContactRecord<unknown>(_sessionKey, LENS_BOOK_RECORD_ID, ownerFingerprint, row.value);
  if (typeof rec !== 'string') throw new Error('lens grant book unreadable: decrypted payload is not a book');
  return rec;
}

/** Persist the serialized grant book, encrypted at rest (fail-closed: throws if locked — never plaintext). */
export async function writeLensGrantBook(ownerFingerprint: string, raw: string): Promise<void> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store the lens grant book unencrypted (fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, LENS_BOOK_RECORD_ID, ownerFingerprint, raw);
  await txPut('settings', { key: lensBookSettingKey(ownerFingerprint), value: payload });
}

// ── #588 piece B: one-time BEACON deposit seeds (DARK; nothing calls these yet) ────────────────────────────────
// The one-time Ed25519 seeds the client needs to sign a later poll/withdraw for a deposit it made. A seed is a secret: encrypted at rest through the
// SAME AAD-bound path as the records above (a reserved id, so a blob can't be transplanted onto a contact row or another owner), owner-local, never on
// the wire, NOT in the .svrnty backup (packVault takes an explicit contents object; after a restore the client re-deposits).
const BEACON_SEEDS_RECORD_ID = 'piece588:beacon-seeds'; // reserved AAD id
function beaconSeedsSettingKey(ownerFingerprint: string): string {
  return `beacon_seeds:${ownerFingerprint}`;
}

/** The seed map exists but cannot be opened (damaged, sealed under another passphrase, not a valid map). It is NEVER read as empty and NEVER overwritten: every
 * caller that needs a seed fails closed, and the owner is told (see beacon-secrets.ts, which surfaces it once and offers an explicit repair). */
export class BeaconSeedsUnreadable extends Error {
  readonly code = 'unreadable' as const;
  constructor(message = 'beacon seeds: a stored row cannot be opened; refusing to overwrite it') { super(message); this.name = 'BeaconSeedsUnreadable'; }
}
/** The session is locked: nothing can be read or written (fail-closed). Not a damaged map: unlocking is the whole remedy. */
export class BeaconSeedsLocked extends Error {
  readonly code = 'locked' as const;
  constructor(message = 'Session locked — refusing to touch beacon seeds (fail-closed)') { super(message); this.name = 'BeaconSeedsLocked'; }
}

/**
 * STRICT read of the seed map: an ABSENT row is the empty map ({}), a row that exists but cannot be opened THROWS BeaconSeedsUnreadable, a locked session
 * THROWS BeaconSeedsLocked. Use this, never getBeaconSeeds, for anything that decides on what it read: getBeaconSeeds answers null for absent AND unreadable.
 */
export async function readBeaconSeeds(ownerFingerprint: string): Promise<BeaconSeeds> {
  if (!_sessionKey) throw new BeaconSeedsLocked();
  const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>('settings', beaconSeedsSettingKey(ownerFingerprint));
  if (!row) return {};
  if (!row.value) throw new BeaconSeedsUnreadable('beacon seeds: a stored row is not readable; refusing to overwrite it');
  let m: unknown;
  try { m = await decryptContactRecord<unknown>(_sessionKey, BEACON_SEEDS_RECORD_ID, ownerFingerprint, row.value); }
  catch { throw new BeaconSeedsUnreadable(); }
  if (!isBeaconSeeds(m)) throw new BeaconSeedsUnreadable('beacon seeds: a stored row is not a valid seed map; refusing to overwrite it');
  return m;
}

/** Read the seed map. FAIL-CLOSED: null on ANY doubt (locked / absent / decrypt-fail / malformed). null is AMBIGUOUS (absent vs unreadable): do NOT decide on it, and do not write after it; use readBeaconSeeds (strict) or updateBeaconSeeds. No application code calls this (a static test pins that). */
export async function getBeaconSeeds(ownerFingerprint: string): Promise<BeaconSeeds | null> {
  if (!_sessionKey) return null;
  try {
    const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>(
      'settings', beaconSeedsSettingKey(ownerFingerprint),
    );
    if (!row?.value) return null;
    const map = await decryptContactRecord<unknown>(_sessionKey, BEACON_SEEDS_RECORD_ID, ownerFingerprint, row.value);
    return isBeaconSeeds(map) ? map : null;
  } catch {
    return null;
  }
}

/**
 * THE EXPLICIT REPAIR for an unreadable seed map: replaces whatever is stored (readable or not) with an empty map. It DESTROYS every held one-time seed, which
 * is why nothing calls it automatically: the owner chooses it, after being told what it destroys (see beacon-secrets.ts). Consequence of the loss, so the
 * copy stays honest: a deposit whose seed is gone can no longer be polled or withdrawn by this client; it lapses at the end of its epoch (plus the grace
 * window), and the next renewal makes a new one. Refuses when locked.
 */
export async function destroyBeaconSeedsAndStartOver(ownerFingerprint: string): Promise<void> {
  if (!_sessionKey) throw new BeaconSeedsLocked('Session locked — refusing to reset beacon seeds (fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, BEACON_SEEDS_RECORD_ID, ownerFingerprint, {});
  await txPut('settings', { key: beaconSeedsSettingKey(ownerFingerprint), value: payload });
}

/**
 * TEST CONTROL ONLY. A BLIND put of the whole map: two tabs lose each other's updates, and a caller that read "no seeds" from the ambiguous getBeaconSeeds
 * overwrites every held one-time seed. No application code may call it (a static test pins that): use updateBeaconSeeds. It stays, renamed, only so the
 * browser spec can show what the blind version does (its control). It still encrypts before it writes and refuses when locked.
 */
export async function setBeaconSeedsUnsafeForTest(ownerFingerprint: string, map: BeaconSeeds): Promise<void> {
  if (!_sessionKey) throw new Error('Session locked — refusing to store beacon seeds unencrypted (fail-closed)');
  if (!isBeaconSeeds(map)) throw new Error('refusing to store a malformed beacon seed map');
  const payload = await encryptContactRecord(_sessionKey, BEACON_SEEDS_RECORD_ID, ownerFingerprint, map);
  await txPut('settings', { key: beaconSeedsSettingKey(ownerFingerprint), value: payload });
}

/**
 * ATOMIC read-modify-write of the seed map. setBeaconSeeds is a blind put (two tabs lose updates) and getBeaconSeeds answers null for BOTH "absent" and "present but unreadable",
 * so a caller that reads null as "no seeds yet" and writes would destroy every held one-time seed. This is the only safe way to change the map:
 *  - ABSENT row: an empty map is the starting point (the one allowed case).
 *  - a row that exists but cannot be opened, or is not a valid seed map: THROWS and writes nothing. It is never read as empty and never overwritten.
 *  - the write commits only if the row is still exactly the one that was read (commitIfUnchanged compares inside one transaction); a lost race re-reads and retries.
 * `mutate` gets the current map (a fresh object) and returns the next one; it must not touch storage. Returns the committed map.
 */
export async function updateBeaconSeeds(ownerFingerprint: string, mutate: (cur: BeaconSeeds) => BeaconSeeds): Promise<BeaconSeeds> {
  if (!_sessionKey) throw new BeaconSeedsLocked('Session locked — refusing to update beacon seeds (fail-closed)');
  const key = beaconSeedsSettingKey(ownerFingerprint);
  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>('settings', key);
    let cur: BeaconSeeds = {};
    if (row) {
      if (!row.value) throw new BeaconSeedsUnreadable('beacon seeds: a stored row is not readable; refusing to overwrite it');
      let m: unknown;
      try { m = await decryptContactRecord<unknown>(_sessionKey, BEACON_SEEDS_RECORD_ID, ownerFingerprint, row.value); }
      catch { throw new BeaconSeedsUnreadable(); }
      if (!isBeaconSeeds(m)) throw new BeaconSeedsUnreadable('beacon seeds: a stored row is not a valid seed map; refusing to overwrite it');
      cur = m;
    }
    const next = mutate({ ...cur });
    if (!isBeaconSeeds(next)) throw new Error('refusing to store a malformed beacon seed map');
    const payload = await encryptContactRecord(_sessionKey, BEACON_SEEDS_RECORD_ID, ownerFingerprint, next);
    const won = await commitIfUnchanged(await openDB(), [{ store: 'settings', key, expected: row ?? null }], [{ store: 'settings', value: { key, value: payload } }]);
    if (won) return next;
  }
  throw new Error('beacon seeds: could not commit the update');
}

// ── #822 (a) S2b-1: the CONFIRMED pairs (DARK; nothing calls the writer except the live ceremony) ─────────────────────────────────
// Which pairs this device has confirmed by a LIVE exchange (see beacon-confirmed.ts for the one rule). DEVICE-LOCAL pairing state: sealed like the seeds (a reserved AAD
// id), owner-local, never on the wire, NEVER in any export and NEVER restored: a restored device starts with nothing confirmed.
const BEACON_CONFIRMED_RECORD_ID = 'piece822:beacon-confirmed'; // reserved AAD id
function beaconConfirmedSettingKey(ownerFingerprint: string): string {
  return `beacon_confirmed:${ownerFingerprint}`;
}
/** The confirmed row exists but cannot be opened. It is NEVER read as empty and NEVER overwritten. */
export class BeaconConfirmedUnreadable extends Error {
  readonly code = 'unreadable' as const;
  constructor(message = 'beacon confirmed: a stored row cannot be opened; refusing to overwrite it') { super(message); this.name = 'BeaconConfirmedUnreadable'; }
}
/** The session is locked: nothing can be read or written (fail-closed). */
export class BeaconConfirmedLocked extends Error {
  readonly code = 'locked' as const;
  constructor(message = 'Session locked — refusing to touch the confirmed pairs (fail-closed)') { super(message); this.name = 'BeaconConfirmedLocked'; }
}

/** STRICT read: an ABSENT row is the empty map; a row that exists but cannot be opened THROWS; a locked session THROWS. */
export async function readBeaconConfirmed(ownerFingerprint: string): Promise<BeaconConfirmed> {
  if (!_sessionKey) throw new BeaconConfirmedLocked();
  const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>('settings', beaconConfirmedSettingKey(ownerFingerprint));
  if (!row) return {};
  if (!row.value) throw new BeaconConfirmedUnreadable('beacon confirmed: a stored row is not readable; refusing to overwrite it');
  let m: unknown;
  try { m = await decryptContactRecord<unknown>(_sessionKey, BEACON_CONFIRMED_RECORD_ID, ownerFingerprint, row.value); }
  catch { throw new BeaconConfirmedUnreadable(); }
  if (!isBeaconConfirmed(m)) throw new BeaconConfirmedUnreadable('beacon confirmed: a stored row is not a valid map; refusing to overwrite it');
  return m;
}

/** ATOMIC read-modify-write of the confirmed map (the same shape as updateBeaconSeeds): an absent row starts empty; an unreadable one THROWS and writes nothing. */
async function updateBeaconConfirmed(ownerFingerprint: string, mutate: (cur: BeaconConfirmed) => BeaconConfirmed): Promise<BeaconConfirmed> {
  if (!_sessionKey) throw new BeaconConfirmedLocked('Session locked — refusing to update the confirmed pairs (fail-closed)');
  const key = beaconConfirmedSettingKey(ownerFingerprint);
  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>('settings', key);
    let cur: BeaconConfirmed = {};
    if (row) {
      if (!row.value) throw new BeaconConfirmedUnreadable('beacon confirmed: a stored row is not readable; refusing to overwrite it');
      let m: unknown;
      try { m = await decryptContactRecord<unknown>(_sessionKey, BEACON_CONFIRMED_RECORD_ID, ownerFingerprint, row.value); }
      catch { throw new BeaconConfirmedUnreadable(); }
      if (!isBeaconConfirmed(m)) throw new BeaconConfirmedUnreadable('beacon confirmed: a stored row is not a valid map; refusing to overwrite it');
      cur = m;
    }
    const next = mutate({ ...cur });
    if (!isBeaconConfirmed(next)) throw new Error('refusing to store a malformed confirmed map');
    const payload = await encryptContactRecord(_sessionKey, BEACON_CONFIRMED_RECORD_ID, ownerFingerprint, next);
    const won = await commitIfUnchanged(await openDB(), [{ store: 'settings', key, expected: row ?? null }], [{ store: 'settings', value: { key, value: payload } }]);
    if (won) return next;
  }
  throw new Error('beacon confirmed: could not commit the update');
}

/** The LOCAL id of the pair with this contact on THIS device (the blinded id every beacon row is keyed by). Needs the unlocked session. */
export async function beaconPairIdFor(contactFingerprint: string): Promise<string> {
  if (!_contactKeys) throw new BeaconConfirmedLocked();
  return beaconPairId(_contactKeys.indexKey, contactFingerprint);
}

/** The port the beacon client asks "is this pair confirmed?" through: reads the confirmed row; ANY doubt answers false. */
export function createBeaconConfirmedPort(ownerFingerprint: string): PairConfirmedPort {
  return createConfirmedPort(() => readBeaconConfirmed(ownerFingerprint));
}

/** Mark this contact's pair confirmed at this generation. The ONLY writer: called from the live ceremony, never from an import, a file or the wire. */
export async function markBeaconPairConfirmed(ownerFingerprint: string, contactFingerprint: string, generation: number): Promise<void> {
  const pairId = await beaconPairIdFor(contactFingerprint);
  await updateBeaconConfirmed(ownerFingerprint, (cur) => withConfirmed(cur, pairId, generation));
}

// ── #588 D1/D2: the identity's beacon key record (x + generation + jitter secret) — IDENTITY STATE, DARK ─────────────────────
// ONE value per identity, lazily created the first time trust is needed (never at genesis), encrypted at rest on the same AAD-bound path as the seeds,
// carried in the backup as keys.beacon (optional, additive), STRICTLY validated on restore, and never overwritten once held.
const BEACON_KEY_RECORD_ID = 'piece588:beacon-key'; // reserved AAD id
function beaconKeySettingKey(ownerFingerprint: string): string {
  return `beacon_key:${ownerFingerprint}`;
}

/** What a read of the record found. 'none' = no row is held (no trust key was ever needed); this is knowable while locked, since looking for the row needs no
 * key. 'unreadable' = a row IS held but cannot be opened (locked session, decrypt-fail, malformed), or the look itself failed (storage error): the honest answer
 * on ANY doubt about a row that may exist. Only 'held' carries a record. */
export type BeaconKeyRead = { state: 'none' } | { state: 'held'; record: BeaconKeyRecord } | { state: 'unreadable' };

export async function readBeaconKeyRecord(ownerFingerprint: string): Promise<BeaconKeyRead> {
  try {
    // Whether a row exists is knowable WITHOUT the session key: this is a raw read, only the decrypt needs the key. So a locked session with no row
    // is 'none' (nothing is held, nothing can be lost) and only a row we cannot open is 'unreadable'. An identity whose keys are not encrypted at rest
    // never gets a session key, and must not be told a trust key it never had "could not be read".
    const row = await txGet<{ key: string; value: { iv: string; ciphertext: string; enc_version?: number } }>(
      'settings', beaconKeySettingKey(ownerFingerprint),
    );
    if (!row?.value) return { state: 'none' };
    if (!_sessionKey) return { state: 'unreadable' };
    const rec = await decryptContactRecord<unknown>(_sessionKey, BEACON_KEY_RECORD_ID, ownerFingerprint, row.value);
    return isBeaconKeyRecord(rec) ? { state: 'held', record: rec } : { state: 'unreadable' };
  } catch {
    return { state: 'unreadable' };
  }
}

/** Read the record. FAIL-CLOSED: null on ANY doubt (locked / absent / decrypt-fail / malformed). Callers that must tell "absent" from "unreadable" (the
 * backup export) use readBeaconKeyRecord. */
export async function getBeaconKeyRecord(ownerFingerprint: string): Promise<BeaconKeyRecord | null> {
  const r = await readBeaconKeyRecord(ownerFingerprint);
  return r.state === 'held' ? r.record : null;
}

/** The record, creating it if (and only if) none is held. Atomic: two tabs racing both end up with the SAME record. Throws when locked, and when a record
 * is held but cannot be read (it is never overwritten). */
export async function ensureBeaconKeyRecord(ownerFingerprint: string, nowMs: number = Date.now()): Promise<BeaconKeyRecord> {
  if (!_sessionKey) throw new Error('Session locked — refusing to create the beacon key unencrypted (fail-closed)');
  const held = await getBeaconKeyRecord(ownerFingerprint);
  if (held) return held;
  const rec = await newBeaconKeyRecord(nowMs);
  const payload = await encryptContactRecord(_sessionKey, BEACON_KEY_RECORD_ID, ownerFingerprint, rec);
  const r = await txAdd('settings', { key: beaconKeySettingKey(ownerFingerprint), value: payload });
  if (r === 'exists') {
    const winner = await getBeaconKeyRecord(ownerFingerprint);
    if (winner) return winner;
    throw new Error('a beacon key record is already held but cannot be read; refusing to overwrite it');
  }
  return rec;
}

/** The RESTORE path: strictly validate a record from a backup and store it ONLY if none is held. 'invalid' = not a valid record (nothing written). */
export async function importBeaconKeyRecord(ownerFingerprint: string, candidate: unknown): Promise<'added' | 'exists' | 'invalid'> {
  if (!isBeaconKeyRecord(candidate)) return 'invalid';
  if (!_sessionKey) throw new Error('Session locked — refusing to store the beacon key unencrypted (fail-closed)');
  const payload = await encryptContactRecord(_sessionKey, BEACON_KEY_RECORD_ID, ownerFingerprint, candidate);
  return txAdd('settings', { key: beaconKeySettingKey(ownerFingerprint), value: payload });
}

/**
 * EVERY owner-sealed record in `settings`: a payload under the session key, a reserved id, and the owner as authenticated data. This list is the one place
 * that names them: the restore's passphrase check opens each one that is present, and its before/after snapshot compares each one. A new sealed record MUST be
 * added here; a static test fails when an encryptContactRecord(_sessionKey, <ID>, ...) call site uses an id that is not listed.
 *
 * THE BEACON ROWS, CLASSIFIED for the go-live gate. None of them is in the backup, so on a fresh device each starts empty. CACHE = rebuilt or re-earned with nothing
 * weakened. TIGHTENING = it records a stop, so losing it silently loosens. Read from the code; no restore-a-removed-pair test pins this yet (that is the gate's job).
 *  - latch rows (beacon_latch:<owner>:local|remote:<pair>, sealed with a caller-chosen AAD, not listed above because they are a collection): TIGHTENING. A 'removed' latch is the
 *    Remove / Block stop, and a Remove made while the switch is off is recorded here too (the local latch, beacon-wire.ts). Every row is opened by the restore check below.
 *  - pair rows (beacon_pair:<owner>:<pair>, same collection rule): MIXED, so treat as TIGHTENING. pendingWithdraws (a deposit still owed a withdrawal), spentEpochs (an epoch
 *    whose slot was withdrawn is never deposited again) and the deletion tombstones are stops; refusedEpochs, firstMatchEpoch and observedMatch are caches or facts, not stops.
 *  - 'beacon-seeds': not a tightening itself but the secret that SIGNS a later withdraw. Without it a deposit already made cannot be withdrawn from this device; after a
 *    restore the client re-deposits (beacon-seeds.ts). Whether the relay still holds such a deposit, and for how long, is not checked here.
 *  - 'beacon-key': this device's own key material, neither. The restore path imports it only when none is held (importBeaconKeyRecord).
 *  - 'beacon-confirmed': a permission, not a stop. Absent means no request is made for the pair, so losing it is safe (the pair has to be confirmed again).
 *  - 'removed-contacts': TIGHTENING. The durable ids of contacts the owner removed, the only thing a restore can rebuild a Remove latch from (a latch row holds a one-way pair id and a kind).
 *    It travels in the passphrase-authenticated vault only, and only Removes recorded after it existed are in it.
 *  - 'suppression-pending': not a stop. Left by a restore when the backup said global off and this device had no record; losing it means the person is never asked and stays private.
 */
export const OWNER_SEALED_SETTINGS: ReadonlyArray<{ name: string; recordId: string; settingKey: (ownerFingerprint: string) => string }> = [
  { name: 'suppression', recordId: SUPPRESSION_RECORD_ID, settingKey: suppressionSettingKey },
  { name: 'held-affirms', recordId: HELD_AFFIRMS_RECORD_ID, settingKey: heldAffirmsSettingKey },
  { name: 'delivery-default', recordId: DELIVERY_RECORD_ID, settingKey: deliverySettingKey },
  { name: 'lens-book', recordId: LENS_BOOK_RECORD_ID, settingKey: lensBookSettingKey },
  { name: 'beacon-seeds', recordId: BEACON_SEEDS_RECORD_ID, settingKey: beaconSeedsSettingKey },
  { name: 'beacon-key', recordId: BEACON_KEY_RECORD_ID, settingKey: beaconKeySettingKey },
  { name: 'beacon-confirmed', recordId: BEACON_CONFIRMED_RECORD_ID, settingKey: beaconConfirmedSettingKey },
  { name: 'removed-contacts', recordId: REMOVED_RECORD_ID, settingKey: removedSettingKey },
  { name: 'suppression-pending', recordId: SUPPRESSION_PENDING_RECORD_ID, settingKey: suppressionPendingSettingKey },
];

export async function listIdentities(): Promise<IdentityRecord[]> {
  return txGetAll('identities');
}

// ── Key operations ──────────────────────────────────────────────

export async function storeKey(fingerprint: string, privateKey: string, passphrase: string): Promise<void> {
  // Blocker-C fail-closed: never write key material as plaintext at rest. The caller MUST
  // initSessionKey() first — genesis (passphrase-mandatory) and every recovery/import path
  // establishes it. Mirrors the contacts fail-closed (addContact); a locked session throws
  // instead of silently falling back to plaintext.
  if (!_sessionKey) {
    throw new Error('Session locked — refusing to store key material as plaintext (Blocker-C fail-closed). Call initSessionKey() first.');
  }
  const encrypted = await encryptKeyData({ privateKey, passphrase });
  await txPut('keys', { fingerprint, ...encrypted });
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
  if (_sessionKey && _unlockVerifiedOwners.has(fingerprint) && record.privateKey) {
    const encrypted = await encryptKeyData({ privateKey: record.privateKey, passphrase: record.passphrase });
    await txPut('keys', { fingerprint, ...encrypted });
  }

  return { privateKey: record.privateKey, passphrase: record.passphrase };
}

/**
 * Non-destructively verify a passphrase against the at-rest key record — WITHOUT touching the
 * live session key. Derives a candidate key from `passphrase` + the record's stored salt and
 * attempts to AES-GCM-decrypt the record; a successful GCM auth proves `passphrase` is the real
 * vault passphrase (the one whose PBKDF2 output encrypted this record).
 *
 * Use this to confirm a re-typed passphrase before acting on it (e.g. biometric device-unlock
 * wraps the typed passphrase for later replay). Do NOT validate by comparing against
 * loadKey().passphrase: that plaintext field can diverge from the live unlock passphrase
 * (restore/import paths store '', and a passphrase change re-keys the record without rewriting
 * the field). Fail-closed: returns false for a missing, legacy-unencrypted, or malformed record,
 * or on any decrypt failure. Non-destructive: never mutates _sessionKey/_sessionSalt.
 */
export async function verifyPassphrase(fingerprint: string, passphrase: string): Promise<boolean> {
  const record = await txGet<any>('keys', fingerprint);
  if (
    !record ||
    record.enc_version !== ENC_VERSION ||
    typeof record.salt !== 'string' ||
    typeof record.iv !== 'string' ||
    typeof record.ciphertext !== 'string'
  ) {
    return false; // no encrypted-at-rest record to verify against (fail-closed)
  }
  try {
    const candidateKey = await deriveSessionKey(passphrase, fromBase64(record.salt));
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(record.iv) },
      candidateKey,
      fromBase64(record.ciphertext),
    );
    return true; // GCM auth passed → passphrase is the vault passphrase
  } catch {
    return false; // wrong passphrase (GCM auth fail) or any error
  }
}

// ── Restore key-domain guard ──────────────────────────────

/** One record this device holds for an owner, and where the key that opens it comes from. */
/**
 * What state a held record is in. 'encrypted': in the current format, every field an opener needs is there. 'legacy': the old UNENCRYPTED form, positively identified (no
 * enc_version AND the old plaintext shape): under no passphrase, so nothing can be orphaned and unlock heals it. 'malformed': anything else: an enc_version that is present but
 * not the current one, an encrypted record missing a field, a row with no recognisable shape. A malformed record is never skipped: the checks refuse.
 */
type HeldForm = 'encrypted' | 'legacy' | 'malformed';

/** One record this device holds for an owner, and where the key that opens it comes from. */
interface HeldRecord {
  kind: 'key' | 'contact' | 'sealed' | 'beacon';
  /** 'record-salt': the key is derived with the salt written in the record itself. 'settings-salt': it is the session key (the device's `key_encryption_salt`). */
  keySource: 'record-salt' | 'settings-salt';
  /** For 'record-salt' records, that salt. */
  salt?: string;
  form: HeldForm;
  /** Opens it with this key: false or a throw means "does not open". Only called when the form is 'encrypted'. */
  open: (key: CryptoKey) => Promise<boolean>;
}

/** The field that identifies a key store's old plaintext form (loadKey, loadPQKeys, loadVault, loadShards). device_mailbox has none: it was born encrypted, so a record there without the current enc_version is corrupt. */
const LEGACY_KEY_SHAPE: Record<string, ((r: Record<string, unknown>) => boolean) | undefined> = {
  keys: (r) => typeof r.privateKey === 'string',
  pq_keys: (r) => typeof r.bundle === 'object' && r.bundle !== null,
  vaults: (r) => typeof r.vault === 'object' && r.vault !== null,
  shards: (r) => typeof r.shards_data === 'object' && r.shards_data !== null,
  device_mailbox: undefined,
};

function keyRecordForm(store: string, r: Record<string, unknown>): HeldForm {
  if (r.enc_version === ENC_VERSION) return typeof r.salt === 'string' && typeof r.iv === 'string' && typeof r.ciphertext === 'string' ? 'encrypted' : 'malformed';
  if (r.enc_version !== undefined) return 'malformed'; // present, but not the current version
  return LEGACY_KEY_SHAPE[store]?.(r) ? 'legacy' : 'malformed'; // no enc_version: legacy only when the old plaintext shape is positively there
}

function contactRowForm(r: Record<string, unknown>): HeldForm {
  if (r.enc_version === CONTACT_ENC_VERSION) return typeof r.iv === 'string' && typeof r.ciphertext === 'string' ? 'encrypted' : 'malformed';
  if (r.enc_version !== undefined) return 'malformed';
  return ['fingerprint', 'name', 'email', 'public_key'].every((f) => typeof r[f] === 'string') ? 'legacy' : 'malformed';
}

/** A sealed payload ({ iv, ciphertext, enc_version }) of a settings record or a beacon row: there is no old plaintext form for these, so it is encrypted or malformed. */
function sealedPayloadForm(p: { iv?: unknown; ciphertext?: unknown; enc_version?: unknown } | null | undefined): HeldForm {
  if (!p || typeof p.iv !== 'string' || typeof p.ciphertext !== 'string') return 'malformed';
  return p.enc_version === undefined || p.enc_version === CONTACT_ENC_VERSION ? 'encrypted' : 'malformed';
}

/**
 * THE ONE DEFINITION of what a device holds for an owner. Three questions are answered from it and from nothing else, so they cannot disagree about what counts:
 * deviceHoldsOwner (is the set non-empty), passphraseOpensEveryHeldKeyRecord (does this passphrase open every encrypted member) and sessionOpensOwner (does the open
 * session). A record type added here is seen by all three; one left out is a hole (held, never checked) or a dead end (checked, never openable) for all three.
 * Members: the key stores, the contact rows, every OWNER_SEALED_SETTINGS record, and every beacon pair and latch row (collections: each row is a member).
 * NOT a member: the contact book manifest. It is a MAC over the book, not a record that can be opened, and nothing is orphaned by it (every contact write rewrites it);
 * counting it would hold a device with nothing to open, and the restore would then refuse under every passphrase, the right one included.
 * Reads only.
 */
async function readHeldSet(fingerprint: string): Promise<HeldRecord[]> {
  const held: HeldRecord[] = [];
  for (const store of OWNER_KEY_STORES) {
    const record = await txGet<{ enc_version?: number; salt?: unknown; iv?: unknown; ciphertext?: unknown }>(store, fingerprint);
    if (!record) continue;
    held.push({ kind: 'key', keySource: 'record-salt', salt: typeof record.salt === 'string' ? record.salt : undefined, form: keyRecordForm(store, record as Record<string, unknown>), open: (key) => keyRecordOpens(record, key, ENC_VERSION) });
  }
  // Contacts and every owner-sealed settings record are under the session key (the settings salt), not under a record's own salt. Key rows under B beside a contact or a
  // sealed record (a blocklist, the receipts default, ...) under A is the two-passphrase state, and a restore that wrote more rows there would read as "stopped partway"
  // on every re-run, or leave a record unreadable for good.
  for (const rec of await txGetByIndex<any>('contacts', 'owner', fingerprint)) {
    if (!rec) continue;
    held.push({ kind: 'contact', keySource: 'settings-salt', form: contactRowForm(rec), open: async (key) => { await decryptContactRecord(key, rec.id, rec.owner_fingerprint, { enc_version: rec.enc_version, iv: rec.iv, ciphertext: rec.ciphertext }); return true; } });
  }
  for (const sealed of OWNER_SEALED_SETTINGS) {
    const row = await txGet<{ key: string; value?: { iv?: unknown; ciphertext?: unknown; enc_version?: number } }>('settings', sealed.settingKey(fingerprint));
    if (!row) continue;
    const value = row.value;
    held.push({ kind: 'sealed', keySource: 'settings-salt', form: sealedPayloadForm(value), open: async (key) => { await decryptContactRecord(key, sealed.recordId, fingerprint, { enc_version: value!.enc_version, iv: value!.iv as string, ciphertext: value!.ciphertext as string }); return true; } });
  }
  // The beacon pair and latch rows (beacon-ports.ts) are COLLECTIONS, so each row is a member, not one per collection. A pair id is derived from the passphrase, so a restore
  // that changed the passphrase-derived keys on a device holding them would orphan every row (the lookups find nothing, read "no latch", and a Block would silently stop
  // applying). They count by themselves: a device with latch rows and NO contacts (a Remove deletes the contact and keeps the latch) is held.
  for (const prefix of beaconRowPrefixes(fingerprint)) {
    for (const key of await txKeysWithPrefix('settings', prefix)) {
      const row = await txGet<{ key: string; value?: unknown }>('settings', key);
      if (!row) continue;
      const aad = beaconRowAad(fingerprint, key);
      const raw = row.value;
      let payload: { iv?: unknown; ciphertext?: unknown; enc_version?: number } | null = null;
      if (aad !== null && typeof raw === 'string') { try { payload = JSON.parse(raw); } catch { payload = null; } }
      const form: HeldForm = aad === null ? 'malformed' : sealedPayloadForm(payload);
      held.push({ kind: 'beacon', keySource: 'settings-salt', form, open: async (k) => { await decryptContactRecord(k, aad!, fingerprint, { enc_version: payload!.enc_version, iv: payload!.iv as string, ciphertext: payload!.ciphertext as string }); return true; } });
    }
  }
  return held;
}

/**
 * Does this device hold this owner, for the passphrase-domain decisions? The held set has at least one member that is not LEGACY (an encrypted one, or a malformed one that
 * the checks must refuse). Presence only: no decryption, no writes. A device holding the owner ONLY in the old unencrypted form is not held: nothing on it is under a
 * passphrase, so nothing can be orphaned, it needs the device-password floor like a fresh one, and unlock heals its rows. A device whose KEYS were cleared but whose settings
 * rows were not (the state a partial wipe leaves) is held and gets the passphrase check.
 * BOUND: on such a device a restore refuses when the passphrase differs or the settings salt is gone, until the latches travel in the backup or are rebuilt fail-closed.
 */
export async function deviceHoldsOwner(fingerprint: string): Promise<boolean> {
  return (await readHeldSet(fingerprint)).some((r) => r.form !== 'legacy');
}

const digestOf = async (value: unknown): Promise<string> =>
  toBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(value)))));

/** Read-only. Throws when any store cannot be read: the caller treats a snapshot it could not take as "unknown", never as "unchanged". */
export async function snapshotOwnerRows(fingerprint: string): Promise<OwnerSnapshot> {
  const out: OwnerSnapshot = {};
  const put = async (place: string, rows: unknown[]) => { out[place] = { n: rows.length, d: await digestOf(rows) }; };
  for (const store of ['identities', ...OWNER_KEY_STORES]) {
    const row = await txGet<unknown>(store, fingerprint);
    await put(store, row ? [row] : []);
  }
  const contacts = (await txGetByIndex<{ id?: string }>('contacts', 'owner', fingerprint)).slice().sort((a, b) => String(a.id).localeCompare(String(b.id)));
  await put('contacts', contacts);
  const manifest = await txGet<unknown>('settings', contactManifestSettingKey(fingerprint));
  await put('contact-manifest', manifest ? [manifest] : []);
  for (const sealed of OWNER_SEALED_SETTINGS) {
    const row = await txGet<unknown>('settings', sealed.settingKey(fingerprint));
    await put(`sealed:${sealed.name}`, row ? [row] : []);
  }
  // The beacon pair and latch rows are COLLECTIONS: one entry per prefix, the count and the digest of the key-sorted key + value rows. A restore never writes them, so an
  // entry that did not change is a runtime check of "a restore does not touch a Block", not only a test assertion; one that did change is read like any other place.
  const [pairPrefix, latchPrefix] = beaconRowPrefixes(fingerprint);
  for (const [place, prefix] of [['beacon-pair-rows', pairPrefix], ['beacon-latch-rows', latchPrefix]] as const) {
    const keys = prefix ? (await txKeysWithPrefix('settings', prefix)).slice().sort() : [];
    const rows: unknown[] = [];
    for (const key of keys) rows.push({ key, value: (await txGet<{ value?: unknown }>('settings', key))?.value });
    await put(place, rows);
  }
  return out;
}

/**
 * Does the OPEN session decrypt every encrypted record this device holds for the owner (the held set, with the session key in place of a derived one)? Whether a record
 * opens is decided by decrypting it, not by comparing salts. A device with no key record is judged on the records it does hold. Non-destructive and fail-closed.
 */
export async function sessionOpensOwner(fingerprint: string): Promise<boolean> {
  const sessionKey = _sessionKey;
  if (!sessionKey) return false;
  return openEveryHeldRecord(fingerprint, async () => sessionKey);
}

/**
 * Does this passphrase open EVERY encrypted record this device holds for the owner (the held set: keys, pq_keys, vaults, shards, device_mailbox, the contact rows, every
 * OWNER_SEALED_SETTINGS record, and EVERY beacon pair and latch row)? Not "the keys record": a restore that died half way can leave records with no `keys` row, and a
 * device holding the owner under TWO passphrases must not accept a restore under either one (it would write more rows beside rows it cannot open). A record still in the
 * old unencrypted form is under no passphrase, so it is skipped, not failed; a malformed encrypted record fails. At least one encrypted record must exist. Reads only.
 */
export async function passphraseOpensEveryHeldKeyRecord(fingerprint: string, passphrase: string): Promise<boolean> {
  const derived = new Map<string, CryptoKey>(); // records written in one session share a salt: derive once per salt
  return openEveryHeldRecord(fingerprint, async (salt) => {
    let key = derived.get(salt);
    if (!key) { key = await deriveSessionKey(passphrase, fromBase64(salt)); derived.set(salt, key); }
    return key;
  });
}

/** The ONE opening loop over the held set: `keyFor(salt)` is where the key comes from (a passphrase derivation, or the open session). false at the first record that does not open. */
async function openEveryHeldRecord(fingerprint: string, keyFor: (salt: string) => Promise<CryptoKey>): Promise<boolean> {
  const held = await readHeldSet(fingerprint);
  let settingsSalt: string | undefined;
  let opened = 0;
  for (const rec of held) {
    if (rec.form === 'legacy') continue;
    if (rec.form === 'malformed') return false;
    let salt = rec.salt;
    if (rec.keySource === 'settings-salt') {
      if (settingsSalt === undefined) settingsSalt = (await txGet<{ key: string; value?: string }>('settings', 'key_encryption_salt'))?.value ?? '';
      salt = settingsSalt;
    }
    if (!salt) return false;
    try {
      if (!(await rec.open(await keyFor(salt)))) return false;
    } catch {
      return false;
    }
    opened++;
  }
  return opened > 0;
}

/**
 * Call after the owner's fingerprint is derived and BEFORE any initSessionKey or write. Throws RestoreDomainRefused when this restore
 * would put the owner's records under a different passphrase than the ones already here. Reads only.
 * initSessionKey itself is deliberately not the guard: a second identity under another passphrase is legitimate.
 */
export async function assertRestoreKeepsOwnerDomain(fingerprint: string, passphrase: string, use: RestoreKeyUse): Promise<void> {
  const held = await deviceHoldsOwner(fingerprint);
  const unlocked = isSessionUnlocked();
  const decision = restoreDomainDecision(use, {
    held,
    unlocked,
    sessionOpens: held && unlocked ? await sessionOpensOwner(fingerprint) : false,
    passphraseOpens: held && passphrase ? await passphraseOpensEveryHeldKeyRecord(fingerprint, passphrase) : false,
  });
  if (decision === 'refuse') throw new RestoreDomainRefused(use);
}

// ── PQ key operations ────────────────────────────────────────────

export async function storePQKeys(fingerprint: string, bundle: any): Promise<void> {
  // Blocker-C fail-closed: never write PQ key material as plaintext at rest (see storeKey).
  if (!_sessionKey) {
    throw new Error('Session locked — refusing to store PQ key material as plaintext (Blocker-C fail-closed). Call initSessionKey() first.');
  }
  const encrypted = await encryptKeyData({ privateKey: JSON.stringify(bundle), passphrase: '' });
  await txPut('pq_keys', { fingerprint, ...encrypted });
}

export async function loadPQKeys(fingerprint: string): Promise<any | null> {
  const record = await txGet<any>('pq_keys', fingerprint);
  if (!record) return null;

  if (record.enc_version === ENC_VERSION) {
    const decrypted = await decryptKeyData(record as EncryptedKeyRecord);
    return JSON.parse(decrypted.privateKey);
  }

  // Legacy unencrypted — auto-migrate if session key available
  if (_sessionKey && _unlockVerifiedOwners.has(fingerprint) && record.bundle) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(record.bundle), passphrase: '' });
    await txPut('pq_keys', { fingerprint, ...encrypted });
  }

  return record.bundle ?? null;
}

// ── Vault operations ─────────────────────────────────────────────

export async function storeVault(fingerprint: string, vault: any): Promise<void> {
  // Blocker-C fail-closed: never write vault key material as plaintext at rest (see storeKey).
  if (!_sessionKey) {
    throw new Error('Session locked — refusing to store vault key material as plaintext (Blocker-C fail-closed). Call initSessionKey() first.');
  }
  const encrypted = await encryptKeyData({ privateKey: JSON.stringify(vault), passphrase: '' });
  await txPut('vaults', { fingerprint, ...encrypted });
}

export async function loadVault(fingerprint: string): Promise<any | null> {
  const record = await txGet<any>('vaults', fingerprint);
  if (!record) return null;

  if (record.enc_version === ENC_VERSION) {
    const decrypted = await decryptKeyData(record as EncryptedKeyRecord);
    return JSON.parse(decrypted.privateKey);
  }

  // Legacy unencrypted — auto-migrate if session key available
  if (_sessionKey && _unlockVerifiedOwners.has(fingerprint) && record.vault) {
    const encrypted = await encryptKeyData({ privateKey: JSON.stringify(record.vault), passphrase: '' });
    await txPut('vaults', { fingerprint, ...encrypted });
  }

  return record.vault ?? null;
}

// ── Device-mailbox operations (piece-2 onion receive keys) ───────
// MY long-lived mailbox keypair: generated once at genesis, vault-persisted (secrets never leave the
// device), published as PUBLIC keys inside the SIGNED identity card. Key material → encrypted at rest
// exactly like the vault (Blocker-C fail-closed: refuse rather than write plaintext). The store is NEW
// in DB v4, so there is NO legacy-plaintext record to migrate — a record that is present but not
// enc_version is corrupt and THROWS (never silently treated as absent, which would regenerate-overwrite).

/** Persist (encrypted) the serialized mailbox keypair for one of my identities. Fail-closed when locked. */
export async function storeDeviceMailbox(
  fingerprint: string,
  serialized: ReturnType<typeof serializeMailboxKeypair>,
): Promise<void> {
  // Blocker-C fail-closed: the mailbox SECRET keys are key material → never plaintext at rest (see storeKey).
  if (!_sessionKey) {
    throw new Error('Session locked — refusing to store device-mailbox key material as plaintext (Blocker-C fail-closed). Call initSessionKey() first.');
  }
  const encrypted = await encryptKeyData({ privateKey: JSON.stringify(serialized), passphrase: '' });
  await txPut('device_mailbox', { fingerprint, ...encrypted });
}

/**
 * Load the mailbox keypair for `fingerprint`. Returns null ONLY when the record is genuinely ABSENT
 * (no identity-mint ran this feature yet → caller lazy-inits). THROWS when a record exists but cannot be
 * decrypted or is malformed — the caller MUST NOT treat that as absent (regenerating on a transient
 * decrypt-fail would churn mailbox_fp + orphan undelivered mail; worse, silently discard recoverable key
 * material). Fail-closed: null ⇒ absent (safe to init); throw ⇒ present-but-unreadable (surface, don't overwrite).
 */
export async function loadDeviceMailbox(fingerprint: string): Promise<MailboxKeypair | null> {
  const record = await txGet<any>('device_mailbox', fingerprint);
  if (!record) return null; // genuinely absent
  if (record.enc_version !== ENC_VERSION) {
    // No legacy-plaintext form ever existed for this v4 store → a non-enc record is corrupt, not legacy.
    throw new Error('device_mailbox record malformed (missing enc_version) — refusing to treat as absent');
  }
  const decrypted = await decryptKeyData(record as EncryptedKeyRecord); // throws on decrypt-fail
  return deserializeMailboxKeypair(JSON.parse(decrypted.privateKey));    // throws on malformed length
}

/**
 * MY own device mailbox — the RECEIVE side (secrets to open onion-delivered mail) + the seal-target I
 * publish — for `fingerprint` (default: the active identity). null when no identity is active or the
 * mailbox is absent (heals on next unlock via ensureDeviceMailboxesOnUnlock). Propagates a decrypt-fail
 * throw from loadDeviceMailbox (surface, don't silently churn). The onion RECEIVE accessor Apollo's
 * emit/receive layer consumes (KB#92278).
 */
export async function getMyDeviceMailbox(
  fingerprint?: string,
): Promise<{ secrets: MailboxSecretKeys; publicKeys: MailboxPublicKeys; fp: string } | null> {
  const fp = (fingerprint || (await getActiveFingerprint()) || '').trim();
  if (!fp) return null;
  const kp = await loadDeviceMailbox(fp);
  if (!kp) return null;
  return {
    secrets: toSecretKeys(kp),
    publicKeys: toPublicKeys(kp),
    fp: deriveMailboxFp(kp.x25519Pub, kp.mlkem1024Pub),
  };
}

/**
 * Generate + persist a fresh device mailbox at identity GENESIS and return its PUBLIC block for the
 * caller to stamp onto the IdentityData wrapper (so the card builder can read it later). Called ONCE,
 * synchronously inside browser-identity.generateIdentity, after the session is unlocked. Fail-closed via
 * storeDeviceMailbox. The keypair is random (NO derivation from any identity/pair secret) — a device-
 * mailbox compromise reads only inbound mail, never the identity key.
 */
export async function initDeviceMailboxAtGenesis(fingerprint: string): Promise<DeviceMailboxPublic> {
  const kp = generateMailboxKeypair();
  await storeDeviceMailbox(fingerprint, serializeMailboxKeypair(kp));
  return mailboxPublicOf(toPublicKeys(kp));
}

/**
 * On unlock, lazily ensure every identity has a device mailbox — heals PRE-FEATURE identities (minted
 * before v4) by generating one and stamping its public block onto the IdentityData wrapper. Best-effort:
 * NEVER throws into the unlock path. Regenerates ONLY on genuine ABSENCE (loadDeviceMailbox===null); on a
 * decrypt-fail/malformed throw it SKIPS (never overwrites possibly-recoverable key material, never churns
 * mailbox_fp on a transient fault). A regenerated mailbox changes mailbox_fp → peers under-reveal to the
 * stale card until a re-exchange (fail-closed liveness fallback; NEVER a re-expose). Does NOT touch any
 * suppression record (that is the spine's genesis-FLOW-only init — a separate store, separate concern).
 */
async function ensureDeviceMailboxesOnUnlock(): Promise<void> {
  if (!_sessionKey) return; // guard; never called locked
  let identities: IdentityRecord[];
  try {
    identities = await listIdentities();
  } catch {
    return;
  }
  for (const idRec of identities) {
    const fp = idRec.fingerprint;
    if (!_unlockVerifiedOwners.has(fp)) continue;
    try {
      const existing = await loadDeviceMailbox(fp); // null = absent; throw = present-but-unreadable
      if (existing) continue; // already has a readable mailbox — nothing to do
      // Absent → lazy-init: generate, persist, and cache the public block on the identity wrapper so
      // the card builder (buildSignedIdentityCard) can carry it without reaching into this store.
      const pub = await initDeviceMailboxAtGenesis(fp);
      try {
        const data = await loadIdentity(fp);
        if (data) {
          data.device_mailbox = pub;
          await storeIdentity(fp, data);
        }
      } catch (e) {
        // The secret is persisted; only the public-block cache failed → card build omits until next
        // unlock heals it (under-reveal, fail-closed). Non-fatal.
        console.warn('[device-mailbox] public-block cache write skipped', fp, e);
      }
    } catch (e) {
      // present-but-unreadable (decrypt-fail/malformed) → do NOT overwrite; surface for recovery.
      console.warn('[device-mailbox] ensure skipped (present but unreadable — not overwriting)', fp, e);
    }
  }
}

// ── Shard operations (social recovery — "the tear") ──────────────
// My own shards are key material → encrypted at rest like the vault.
// Blocker-C fail-closed: refuses rather than writing plaintext pre-unlock
// (same guarantee as keys/pq_keys/vaults).

/** Persist all shards for one of my identities (stops the create-time discard). */
export async function storeShards(fingerprint: string, shardsData: ShardsData): Promise<void> {
  // Blocker-C fail-closed: my own shards are key material → never plaintext at rest (see storeKey).
  if (!_sessionKey) {
    throw new Error('Session locked — refusing to store shard key material as plaintext (Blocker-C fail-closed). Call initSessionKey() first.');
  }
  const encrypted = await encryptKeyData({ privateKey: JSON.stringify(shardsData), passphrase: '' });
  await txPut('shards', { fingerprint, ...encrypted });
}

export async function loadShards(fingerprint: string): Promise<ShardsData | null> {
  const record = await txGet<any>('shards', fingerprint);
  if (!record) return null;

  if (record.enc_version === ENC_VERSION) {
    const decrypted = await decryptKeyData(record as EncryptedKeyRecord);
    return JSON.parse(decrypted.privateKey);
  }

  // Legacy unencrypted — auto-migrate if session key available
  if (_sessionKey && _unlockVerifiedOwners.has(fingerprint) && record.shards_data) {
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

// ── Contact book-integrity manifest (enc-b B4) ───────────────────
// A per-owner HMAC over {(id, version)…, count} (contact-crypto.serializeManifest) catches book-level
// tampering that per-record AES-GCM tags miss: delete, truncation, rollback, insert/reorder. Stored as
// a keyed record in `settings` under `contact_manifest:${owner}`, written in the SAME tx as every
// contact mutation (add/update/remove) via txPutMany so the record and its manifest never diverge
// across a crash. The manifest subkey is per-identity (deriveContactCryptoKeys) and never leaves memory.
// `version` lives INSIDE the encrypted contact body, so entries are gathered by decrypting the owner's
// book (getAllContacts) BEFORE the write tx — never mid-tx (the txPutMany auto-commit footgun).
function contactManifestSettingKey(ownerFingerprint: string): string {
  return `contact_manifest:${ownerFingerprint}`;
}

function toManifestEntry(c: ContactRecord): ManifestEntry {
  return { id: c.id, version: typeof c.version === 'number' ? c.version : 0 };
}

/**
 * Build the settings-store write op carrying the book manifest for `ownerFingerprint` over the given
 * POST-mutation entries. Async (HMAC) — call BEFORE opening the write tx, then hand the returned op to
 * txPutMany alongside the record put/delete. Fail-closed: needs the unlocked manifest subkey.
 */
async function buildContactManifestOp(ownerFingerprint: string, entries: ManifestEntry[]): Promise<TxOp> {
  if (!_contactKeys) {
    throw new Error('Session locked — cannot compute contact manifest (enc-b fail-closed)');
  }
  const mac = await computeManifestMAC(_contactKeys.manifestKey, entries, entries.length);
  return { store: 'settings', value: { key: contactManifestSettingKey(ownerFingerprint), value: mac } };
}

/**
 * Encrypt a logical ContactRecord into its at-rest envelope (fail-closed — throws if locked).
 * Envelope = { id, owner_fingerprint (plaintext: keyPath / 'owner' index / AAD), fingerprint = the
 * BLINDED index HMAC(indexKey, realFp) [omitted when keyless — skips the UNIQUE index],
 * enc_version/iv/ciphertext = AES-GCM(body, AAD id+owner) }. The body is the full record minus the
 * plaintext envelope keys; the real fingerprint stays inside the ciphertext.
 */
async function buildStoredContact(record: ContactRecord): Promise<Record<string, unknown>> {
  if (!_sessionKey || !_contactKeys) {
    throw new Error('Session locked — refusing to store a contact unencrypted (enc-b fail-closed)');
  }
  const { id, owner_fingerprint, ...body } = record;
  const payload = await encryptContactRecord(_sessionKey, id, owner_fingerprint, body);
  const stored: Record<string, unknown> = { id, owner_fingerprint, ...payload };
  const rawFp = (record.fingerprint || '').trim();
  if (rawFp) stored.fingerprint = await blindFingerprint(_contactKeys.indexKey, rawFp);
  return stored;
}

/**
 * addContact REFUSED this row on purpose (its fingerprint does not bind to its key, or it would land trusted without a verification). Typed so a caller can
 * tell a row that was refused from a write that FAILED: only the first is a row to skip and count.
 */
export class ContactRefused extends Error {
  readonly code = 'contact-refused' as const;
  constructor(public readonly reason: 'binding' | 'verify-before-trust', message: string) { super(message); this.name = 'ContactRefused'; }
}

export async function addContact(ownerFingerprint: string, contact: Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'>): Promise<ContactRecord> {
  // enc-b fail-closed (Flint seam Q4): never persist a contact unencrypted. Every add-path must be
  // post-unlock; if locked, refuse (do NOT fall back to plaintext — that was the Blocker-C mistake).
  if (!_sessionKey || !_contactKeys) {
    throw new Error('Session locked — addContact refuses to store plaintext (enc-b fail-closed)');
  }
  // Invariant-1: a fingerprint exists only with a bound key.
  // Keyless rows MUST NOT carry a fingerprint (even a placeholder).
  const pk = (contact.public_key || '').trim();
  if (!pk) {
    contact = { ...contact, fingerprint: '', public_key: '' };
  } else if (!(await fingerprintMatchesKey(contact.fingerprint, pk, {
    kem_public_key: contact.pq_kem_public_key,
    sig_public_key: contact.pq_sig_public_key,
  }))) {
    // C2 / Invariant-1: fail-closed when a key is present —
    // refuse mismatched attacker-key + victim-fingerprint pairs.
    throw new ContactRefused('binding', 'fingerprint↔key binding failed — refusing to store a contact whose fingerprint does not match its public key');
  }
  const id = crypto.randomUUID();
  const record: ContactRecord = {
    ...contact,
    id,
    owner_fingerprint: ownerFingerprint,
    added_at: new Date().toISOString(),
  };
  // Keyless/gray contacts (vCard import) have no fingerprint. buildStoredContact omits the (blinded)
  // fingerprint field for keyless records → they skip the UNIQUE index (IndexedDB skips ABSENT keys),
  // so multiple grays coexist. Normalize the logical record the same way (absent fp/pk = keyless).
  if (!record.fingerprint) delete (record as { fingerprint?: string }).fingerprint;
  if (!(record.public_key || '').trim()) delete (record as { public_key?: string }).public_key;
  // pt5 verify-before-trust (SINK gate, CREATE path — mirrors updateContact's promotion gate): never
  // CREATE a contact already-trusted without a real owner-verification, so no path (add OR update)
  // reaches trusted-unverified. Normal adds are unverified → unaffected; a verified add (e.g. in-person
  // sample) passes. Fail-closed.
  {
    const addTrusted = record.trust_level === 'trusted' || record.trust_level === 'verified' || (record as { trusted?: boolean }).trusted === true;
    if (addTrusted && !ownerHasVerified(record as Parameters<typeof ownerHasVerified>[0])) {
      throw new ContactRefused('verify-before-trust', 'verify-before-trust: refusing to create a trusted contact without owner verification (in-person / other-channel). [pt5 survivor-safety gate]');
    }
  }
  const stored = await buildStoredContact(record);
  // enc-b B4: recompute the book manifest over the POST-insert set (existing owner contacts + this new
  // record) and write it in the SAME tx as the record. Decrypt-all + MAC happen BEFORE the tx (the
  // auto-commit footgun). A ConstraintError aborts BOTH puts → the book and manifest stay consistent.
  // The manifest is built from a read of the whole book, so it is compared at commit time like an update's: it is read BEFORE the book, and the
  // write goes through only if it is still what was read (and the new id is still absent); otherwise the book is read again (up to the cap).
  const manifestKey = contactManifestSettingKey(ownerFingerprint);
  try {
    await casRetry(record.id, async () => {
      const manifestBefore = await txGet<Record<string, unknown>>('settings', manifestKey);
      const postAddEntries = [
        ...(await getAllContacts(ownerFingerprint)).map(toManifestEntry),
        { id: record.id, version: typeof record.version === 'number' ? record.version : 0 },
      ];
      const addManifestOp = await buildContactManifestOp(ownerFingerprint, postAddEntries);
      return commitIfUnchanged(
        await openDB(),
        [{ store: 'contacts', key: record.id, expected: null }, { store: 'settings', key: manifestKey, expected: manifestBefore }],
        [{ store: 'contacts', value: stored }, addManifestOp],
      );
    });
  } catch (e) {
    // Idempotent-by-fingerprint (fix at the source, not per-caller): two concurrent add-paths for the
    // same joiner (interval poll vs Galaxy pull-to-refresh; a future websocket live-add) can each pass
    // a getContactByFingerprint pre-check as null, then both insert. The UNIQUE (blinded) fingerprint
    // index catches the 2nd → ConstraintError. Rather than surface it, return the record that WON the
    // race. getContactByFingerprint takes the RAW fp (it blinds internally). Fresh db/txn → clean.
    if (record.fingerprint && (e as { name?: string } | null)?.name === 'ConstraintError') {
      const existing = await getContactByFingerprint(ownerFingerprint, record.fingerprint);
      if (existing) return existing;
    }
    throw e; // any other failure (or missing existing) → preserve the fail-closed contract
  }
  return record;
}

/**
 * An update to a contact: a patch, or a SYNCHRONOUS function from the record updateContact holds NOW to a patch.
 * The function form is for any write that builds a value from a nested field (metadata, tags, a history list): it runs on the record read
 * inside this call, so it cannot write back a copy captured earlier (a dialog opened minutes ago, a list loaded before a loop).
 */
export { ContactConflictError };
export type ContactUpdate = Partial<ContactRecord> | ((existing: ContactRecord) => Partial<ContactRecord>);

/**
 * The merge updateContact performs, pure so it can be tested without IndexedDB: `{ ...existing, ...patch, id: existing.id }`. A function
 * updater is called once with `existing`. It must be synchronous: if it returns a Promise (or anything that is not a plain object) this
 * throws, because an `await` inside would reopen the window between the read and the write that the function form exists to close.
 */
export function mergeContactUpdate(existing: ContactRecord, updates: ContactUpdate): ContactRecord {
  const patch = typeof updates === 'function' ? updates(existing) : updates;
  if (patch === null || typeof patch !== 'object' || Array.isArray(patch) || typeof (patch as { then?: unknown }).then === 'function') {
    throw new Error('updateContact: the updater must synchronously return a plain patch object (not a Promise)');
  }
  return { ...existing, ...patch, id: existing.id };
}

/**
 * The gates a finished contact record must pass before it is stored. They run on every attempt of a write, on the record that attempt
 * decided from. Throws to refuse.
 */
export async function finalizeContactUpdate(existing: ContactRecord, next: ContactRecord): Promise<ContactRecord> {
  // #724: a row's fingerprint is its identity; trust + visibility hang off the row, so an update may never replace it.
  assertFingerprintUnchanged(existing.fingerprint, next.fingerprint);
  const pk = (next.public_key || '').trim();
  // Invariant-1 back-stop: no key ⇒ no fingerprint (impossible to construct keyless fp).
  if (!pk) {
    next.public_key = '';
    delete (next as { fingerprint?: string }).fingerprint;
  } else if (!(await fingerprintMatchesKey(next.fingerprint, pk, {
    kem_public_key: next.pq_kem_public_key,
    sig_public_key: next.pq_sig_public_key,
  }))) {
    throw new ContactUpdateRefused('binding', 'fingerprint↔key binding failed — refusing to update a contact whose fingerprint does not match its public key');
  }
  // pt5 verify-before-trust (survivor-safety SINK gate — Flint seal-criteria #158146 / Archie #92153):
  // block the unverified/known → trusted PROMOTION unless a REAL owner-verification backs it. Every
  // promotion path (bulk-select Trust, TrustMap toggle, card dialog, import-update, future) funnels
  // through updateContact, so gating here is by-construction — no caller can bypass. Reads the REAL
  // owner-verify (ownerHasVerified → owner_verified_at w/ in_person|other_channel), NEVER the top-level
  // trusted-since stamp. Fail-closed. Non-regression: only the TRANSITION is gated (re-saving an already-
  // trusted contact, or un-trusting, passes). This is Peter's pt5 "resistance between known and trusted".
  const wasTrusted = existing.trust_level === 'trusted' || existing.trust_level === 'verified' || (existing as { trusted?: boolean }).trusted === true;
  const nowTrusted = next.trust_level === 'trusted' || next.trust_level === 'verified' || (next as { trusted?: boolean }).trusted === true;
  if (nowTrusted && !wasTrusted && !ownerHasVerified(next as Parameters<typeof ownerHasVerified>[0])) {
    throw new ContactUpdateRefused('verify-before-trust', 'verify-before-trust: refusing to promote a contact to trusted without owner verification (in-person / other-channel). Verify first. [pt5 survivor-safety gate]');
  }
  return next;
}

/**
 * Write `ops` in one transaction, but only if every `expects` row is still exactly what the caller read. The reads happen INSIDE the
 * transaction and the decision is made in the request callbacks (never across an awaited non-IndexedDB promise), so the transaction cannot
 * auto-commit between the compare and the writes. Resolves false, having written nothing, when any row differs. Takes the database as a
 * parameter so it can be tested against a small in-memory fake.
 */
export function commitIfUnchanged(db: IDBDatabase, expects: Expect[], ops: TxOp[]): Promise<boolean> {
  const stores = [...new Set([...expects.map((e) => e.store), ...ops.map((o) => o.store)])];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(stores, 'readwrite');
    let firstError: unknown = null;
    let conflict = false;
    let waiting = expects.length;
    const settle = () => {
      if (conflict) { tx.abort(); return; } // nothing has been written; onabort resolves false
      for (const op of ops) {
        const store = tx.objectStore(op.store);
        const req = 'delete' in op ? store.delete(op.delete) : store.put(op.value);
        // The FIRST error is the real one: once a write fails the transaction aborts, and every request still pending reports an AbortError after it.
        req.onerror = () => { firstError = firstError ?? req.error; };
      }
    };
    for (const e of expects) {
      const req = tx.objectStore(e.store).get(e.key);
      req.onsuccess = () => {
        if (!sameStoredRow((req.result ?? null) as StoredRow, e.expected)) conflict = true;
        if (--waiting === 0) settle();
      };
      req.onerror = () => { firstError = firstError ?? req.error; };
    }
    if (expects.length === 0) settle();
    tx.oncomplete = () => { db.close(); resolve(true); };
    tx.onabort = () => {
      db.close();
      if (conflict && firstError === null) resolve(false);
      else reject(firstError ?? tx.error ?? new Error('transaction aborted'));
    };
    tx.onerror = () => { firstError = firstError ?? tx.error; };
  });
}

const contactCasIO: CasIO<ContactRecord> = {
  readRaw: (id) => txGet<Record<string, unknown>>('contacts', id),
  manifestKey: contactManifestSettingKey,
  readManifest: (owner) => txGet<Record<string, unknown>>('settings', contactManifestSettingKey(owner)),
  decrypt: (raw) => decryptContactIfNeeded(raw),
  finalize: finalizeContactUpdate,
  encrypt: (next) => buildStoredContact(next),
  // enc-b B4: the manifest over the post-update set (this id's version replaced), written in the SAME tx as the record.
  manifestOp: async (owner, next) => {
    const entries = (await getAllContacts(owner)).map((c) =>
      c.id === next.id ? { id: next.id, version: typeof next.version === 'number' ? next.version : 0 } : toManifestEntry(c),
    );
    return buildContactManifestOp(owner, entries);
  },
  commit: async (expects, ops) => commitIfUnchanged(await openDB(), expects, ops),
};

function assertUnlockedForContactWrite(what: string): void {
  // enc-b fail-closed: re-encrypting an update needs the session; refuse when locked.
  if (!_sessionKey || !_contactKeys) {
    throw new Error(`Session locked — ${what} refuses to store plaintext (enc-b fail-closed)`);
  }
}

/**
 * Update a contact by compare-and-swap (see contact-cas.ts): the update is decided on the record read at the start of each attempt and is
 * written only if neither that record nor the book manifest changed meanwhile; otherwise it is decided again on the newer record, up to
 * CAS_MAX_ATTEMPTS, then ContactConflictError (nothing written). A function update MUST be pure: it can run once per attempt.
 */
export async function updateContact(id: string, updates: ContactUpdate): Promise<void> {
  assertUnlockedForContactWrite('updateContact');
  await casUpdateWith(contactCasIO, id, (existing) => mergeContactUpdate(existing, updates));
}

/**
 * Like updateContact, for a decision that may be "do not write": `decide` returns the patch, or null when the record it was given does
 * not call for a write (nothing is written and it is not a conflict). `applied` tells which. `decide` is subject to the same purity rule.
 */
export async function updateContactIf(
  id: string,
  decide: (existing: ContactRecord) => Partial<ContactRecord> | null,
): Promise<{ applied: boolean }> {
  assertUnlockedForContactWrite('updateContactIf');
  const r = await casUpdateWith(contactCasIO, id, (existing) => {
    const patch = decide(existing);
    return patch === null ? null : mergeContactUpdate(existing, patch);
  });
  return { applied: r.applied };
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
  // enc-b B4: delete the record AND rewrite the book manifest over the post-remove set in ONE tx, so a
  // removal can't leave a stale manifest that would false-alarm as corruption on the next unlock.
  const rec = await txGet<{ owner_fingerprint?: string }>('contacts', id);
  if (!rec) return; // idempotent: nothing to remove
  if (!_sessionKey || !_contactKeys) {
    // Removal is a post-unlock user action; recomputing the manifest needs the session. Fail-closed
    // (consistent with add/update) rather than delete-without-manifest and trip a false corruption flag.
    throw new Error('Session locked — removeContact needs the session to update the book manifest (enc-b fail-closed)');
  }
  const owner = rec.owner_fingerprint ?? '';
  const manifestKey = contactManifestSettingKey(owner);
  // Compared at commit time like an update: the manifest and the record are read first, and the delete goes through only if both are unchanged.
  await casRetry(id, async () => {
    const raw = await txGet<Record<string, unknown>>('contacts', id);
    if (!raw) return true; // already gone: removing is idempotent
    const manifestBefore = await txGet<Record<string, unknown>>('settings', manifestKey);
    const postRemoveEntries = (await getAllContacts(owner)).filter((c) => c.id !== id).map(toManifestEntry);
    const removeManifestOp = await buildContactManifestOp(owner, postRemoveEntries);
    return commitIfUnchanged(
      await openDB(),
      [{ store: 'contacts', key: id, expected: raw }, { store: 'settings', key: manifestKey, expected: manifestBefore }],
      [{ store: 'contacts', delete: id }, removeManifestOp],
    );
  });
}

/**
 * Decrypt a stored contact to the full in-memory ContactRecord. Backward-compatible: encrypted
 * records (enc_version present) are AES-GCM-decrypted under _sessionKey (AAD = id+owner); legacy
 * plaintext records pass through unchanged. At rest the `fingerprint` field holds the BLINDED index;
 * the decrypted body carries the real fingerprint, which wins on the merge below.
 */
async function decryptContactIfNeeded(rec: any): Promise<ContactRecord> {
  if (rec && rec.enc_version && rec.ciphertext) {
    if (!_sessionKey) throw new Error('Session locked — cannot decrypt contact');
    const body = await decryptContactRecord<ContactRecord>(
      _sessionKey,
      rec.id,
      rec.owner_fingerprint,
      { enc_version: rec.enc_version, iv: rec.iv, ciphertext: rec.ciphertext },
    );
    return { ...body, id: rec.id, owner_fingerprint: rec.owner_fingerprint };
  }
  return rec as ContactRecord;
}

export async function getContact(id: string): Promise<ContactRecord | null> {
  const rec = await txGet<any>('contacts', id);
  return rec ? decryptContactIfNeeded(rec) : null;
}

export async function getContactByFingerprint(ownerFingerprint: string, fingerprint: string): Promise<ContactRecord | null> {
  // Blinded index: encrypted records store idx = HMAC(indexKey, fp) in the `fingerprint` field.
  // Compute the same idx to look them up. Mixed-state during the on-unlock migration: legacy
  // plaintext records still hold the raw fp, so match either. (idx needs an unlocked session.)
  const idx = _contactKeys ? await blindFingerprint(_contactKeys.indexKey, fingerprint) : null;
  const recs = await txGetByIndex<any>('contacts', 'owner', ownerFingerprint);
  const found = recs.find(c => (idx !== null && c.fingerprint === idx) || c.fingerprint === fingerprint);
  return found ? decryptContactIfNeeded(found) : null;
}

export async function getAllContacts(ownerFingerprint: string): Promise<ContactRecord[]> {
  const recs = await txGetByIndex<any>('contacts', 'owner', ownerFingerprint);
  return Promise.all(recs.map(decryptContactIfNeeded));
}

// ── enc-b B5: on-unlock heal + book-integrity establish/verify ────
function contactIntegritySettingKey(ownerFingerprint: string): string {
  return `contact_integrity:${ownerFingerprint}`;
}

/**
 * Read the book-integrity status for an owner: 'corrupt' if the last unlock found a manifest mismatch
 * (→ prompt cloud restore), else 'ok'. This is a UX hint, not a security control — the manifest MAC is
 * the tamper-evidence; the flag just surfaces it. (Spec point 5: MAC-fail → cloud restore = wiring.)
 */
export async function getContactBookIntegrity(ownerFingerprint: string): Promise<'ok' | 'corrupt'> {
  const flag = await txGet<{ key: string; value: string }>('settings', contactIntegritySettingKey(ownerFingerprint));
  return flag?.value === 'corrupt' ? 'corrupt' : 'ok';
}

/**
 * Heal legacy plaintext contacts to encrypted-at-rest, then establish or verify each owner's book
 * manifest. Called from initSessionKey once the session + contact subkeys are set.
 *  - Idempotent: encrypted records (enc_version present) are skipped.
 *  - Crash-safe/resumable: each record is re-encrypted with txPut OVERWRITE (never delete-then-write),
 *    so a crash mid-sweep just leaves the remainder for the next unlock.
 *  - Manifest-neutral migration: encrypting a record changes neither its id nor its version, so the
 *    {id,version} manifest stays valid across the sweep; we (re)establish/verify once at the end.
 *  - Best-effort: never throws into the unlock path. A manifest MISMATCH sets a per-owner corrupt flag
 *    (settings:contact_integrity:${owner}) for the recovery/cloud-restore UI — it does not raise.
 */
async function migrateAndVerifyContactsOnUnlock(): Promise<void> {
  if (!_sessionKey || !_contactKeys) return; // guard; never called locked
  let stored: Array<Record<string, unknown>>;
  try {
    stored = await txGetAll<Record<string, unknown>>('contacts');
  } catch {
    return; // store unavailable — nothing to do this unlock
  }
  if (stored.length === 0) return; // fresh identity / empty book

  // 1. Migrate plaintext-at-rest contacts (no enc_version) → encrypted envelope, in place.
  for (const rec of stored) {
    if (rec && rec.enc_version) continue; // already encrypted — idempotent skip
    if (!_unlockVerifiedOwners.has(String(rec?.owner_fingerprint))) continue;
    try {
      await txPut('contacts', await buildStoredContact(rec as unknown as ContactRecord));
    } catch (e) {
      console.warn('[enc-b] contact migration skipped a record (retries next unlock)', e);
    }
  }

  // 2. Establish (first run / post-upgrade) or verify the per-owner book manifest over the healed book.
  try {
    const healed = await txGetAll<Record<string, unknown>>('contacts');
    const byOwner = new Map<string, ContactRecord[]>();
    for (const rec of healed) {
      if (!_unlockVerifiedOwners.has(String(rec?.owner_fingerprint))) continue;
      const c = await decryptContactIfNeeded(rec);
      const list = byOwner.get(c.owner_fingerprint) ?? [];
      list.push(c);
      byOwner.set(c.owner_fingerprint, list);
    }
    for (const [owner, contacts] of byOwner) {
      const entries = contacts.map(toManifestEntry);
      const existing = await txGet<{ key: string; value: string }>('settings', contactManifestSettingKey(owner));
      if (!existing) {
        // No baseline yet (existing user upgrading, or first contact) → establish over current book.
        await txPutMany([await buildContactManifestOp(owner, entries)]);
        continue;
      }
      const ok = await verifyManifestMAC(_contactKeys.manifestKey, entries, entries.length, existing.value);
      if (!ok) {
        await txPut('settings', { key: contactIntegritySettingKey(owner), value: 'corrupt' });
        console.warn(`[enc-b] contact book manifest MISMATCH for ${owner} — flagged for recovery`);
      } else {
        // Book verifies → clear any stale corrupt flag from a prior false-alarm/repair.
        await txDelete('settings', contactIntegritySettingKey(owner)).catch(() => {});
      }
    }
  } catch (e) {
    console.warn('[enc-b] contact manifest establish/verify skipped this unlock', e);
  }
}

/**
 * The unlock privacy sweep's decision, pure: for the record held NOW, the patch that clears open_visibility on a contact that is not trusted
 * (a non-trusted contact must not carry it), or an empty patch when there is nothing to do (it is trusted, or it is already private). Other
 * share settings and every other metadata key are kept. `edgeTrusted` is the reveal derivation: an explicit `trusted: false` wins over trust_level.
 */
export function clearOpenVisibilityIfUntrusted(fresh: ContactRecord): Partial<ContactRecord> {
  const md = (fresh.metadata as Record<string, unknown> | undefined) ?? {};
  const ss = (md.share_settings as { open_visibility?: boolean } | undefined) ?? {};
  if (edgeTrusted(fresh as { trusted?: boolean; trust_level?: string }) || ss.open_visibility !== true) return {};
  return { metadata: { ...md, share_settings: { ...ss, open_visibility: false } } } as Partial<ContactRecord>;
}

/**
 * piece-1 / #111-LEGACY sweep (survivor-safety, Archie do-no-harm ruling #158835). The two-layer reveal
 * drops `&& e.trusted` from getKnownPeers — FIX B's read-side mask over legacy untrusted-open edges
 * (#111 FIX A was handler-only, no migration → pre-FIX-A untrust left open_visibility SET). Without this,
 * the drop REVEALS them = unhonored-severance surfacing. This clears open_visibility on every NON-trusted
 * contact → "no untrusted-open edge" true-by-construction → the drop has zero transitional-reveal. Must
 * land WITH the drop. Idempotent (re-run clears nothing new), best-effort (never throws into unlock).
 *
 * ★★ TRUSTED-DEFINITION CONSISTENCY (Athena #158853): `trusted` here MUST match the REVEAL's derivation
 * (contact-edge.ts: `c.trusted ?? (trust_level === 'verified' || 'trusted')`), NOT trust_level-only — an
 * explicit `c.trusted === false` WINS over trust_level (?? short-circuits on the explicit false), so a
 * {trusted:false, trust_level:'trusted'} edge (which the reveal HIDES) is swept and no clamp/reveal gap reopens.
 */
async function migratePerContactPrivacyOnUnlock(): Promise<void> {
  if (!_sessionKey || !_contactKeys) return;
  let stored: Array<Record<string, unknown>>;
  try { stored = await txGetAll<Record<string, unknown>>('contacts'); } catch { return; }
  for (const rec of stored) {
    if (!_unlockVerifiedOwners.has(String(rec?.owner_fingerprint))) continue;
    try {
      const c = await decryptContactIfNeeded(rec);
      // ★★ edgeTrusted (shared reveal derivation): explicit c.trusted===false WINS over trust_level (?? semantics).
      const trusted = edgeTrusted(c as { trusted?: boolean; trust_level?: string });
      const md = (c.metadata as Record<string, unknown>) ?? {};
      const ss = (md.share_settings as { open_visibility?: boolean }) ?? {};
      if (!trusted && ss.open_visibility === true) {
        // Honor the severance: a non-trusted contact must not carry open_visibility (two-layer: UI only
        // sets open_vis on trusted; any untrusted-open edge is legacy #111 drift). Preserve other share_settings.
        // Decided again on the record held when the write runs: a change since the snapshot above (now trusted, or already private) wins.
        // A write that protects the owner: it takes the book lock (shared) and the contact's lock so another tab's poll cannot make it lose its comparison.
        await withSafetyWrite(c.id, () => updateContact(c.id, clearOpenVisibilityIfUntrusted));
      }
    } catch (e) {
      console.warn('[piece-1] #111-legacy privacy sweep skipped a record (retries next unlock)', e);
    }
  }
}

/**
 * #593 affirm-wire removal — one-time, idempotent, logged PURGE of the device-held mutual-trust taint.
 *
 * The removed affirm-wire (deposit→consume→applyMutual) persisted `mutual.{they_trust_me,reciprocal,
 * last_affirm_at}` onto contact records — a device-held "they trust me" bit that is FALSE SECURITY
 * (defeated by inspecting the device). The wire is code-ripped; this scrubs the values it ALREADY WROTE
 * on existing stores (dev users + any two-seat that consumed an affirmation) so the taint doesn't linger.
 *
 * DO-NO-HARM SCOPE (what Flint co-verifies, all-bearers): touches ONLY the three affirm-wire bits — it
 * NEVER touches the owner's own sovereign trust (trusted / trust_level / trusted_since / trust_history) or
 * the rest of the book. `mutual.last_sync` (a benign interaction timestamp, not taint) is PRESERVED;
 * `last_affirm_at` is dropped. Idempotent: a record already at the benign default is skipped (no write),
 * so re-running every unlock is a no-op. Best-effort: a per-record hiccup leaves it for the next unlock
 * and never throws into the unlock path. Mutual is re-grounded on the blind PSI intersection (#588).
 *
 * Runs over txGetAll('contacts') = EVERY contact across ALL owner books in the store (all bearers).
 */
async function purgeAffirmWireMutualTaintOnUnlock(): Promise<void> {
  if (!_sessionKey || !_contactKeys) return;
  let stored: Array<Record<string, unknown>>;
  try { stored = await txGetAll<Record<string, unknown>>('contacts'); } catch { return; }
  let scrubbed = 0;
  for (const rec of stored) {
    if (!_unlockVerifiedOwners.has(String(rec?.owner_fingerprint))) continue;
    try {
      const c = await decryptContactIfNeeded(rec);
      const res = scrubAffirmWireMutual(c.mutual);
      if (!res.changed) continue; // idempotent: already at the benign default → no write
      // Write ONLY the scrubbed `mutual` — nothing else on the record is touched.
      await updateContact((c as { id: string }).id, { mutual: res.mutual } as Partial<ContactRecord>);
      scrubbed++;
    } catch (e) {
      console.warn('[#593] affirm-wire mutual-taint purge skipped a record (retries next unlock)', e);
    }
  }
  if (scrubbed > 0) console.info(`[#593] purged device-held mutual-trust taint from ${scrubbed} contact record(s)`);
}

/**
 * enc-b Blocker-C (eager-migrate half): on unlock, proactively re-encrypt any plaintext-fallback
 * records in the four identity stores (keys / pq_keys / vaults / shards). loadKey/loadPQKeys/loadVault/
 * loadShards already lazy-migrate a plaintext record to encrypted-at-rest as a side effect when the
 * session is unlocked — but only for records that are READ. Recovery material (esp. shards) is read
 * rarely, so a written-never-read-post-unlock plaintext record would otherwise sit exposed indefinitely.
 * Eager-calling the loaders once per identity on unlock heals those stragglers. No re-key (same
 * _sessionKey the lazy path uses). Best-effort: never throws into the unlock path.
 *
 * NOTE: this is the SAFE half of Blocker-C. The OTHER half — removing the `else { plaintext }` fallback
 * branches so storeKey/storePQKeys/storeVault/storeShards are fail-closed — is DEFERRED: a caller audit
 * found live paths (importAll JSON restore, the passphrase-free seed/recovery-code restore, two vault-
 * restore branches) that write identity key material while the session is still locked, so fail-closing
 * as-is would break restore/recovery. That removal needs those paths fixed first + a product decision on
 * the passphrase-free recovery path. Escalated to Flint (security) + Archie (product).
 */
async function eagerMigrateIdentityStoresOnUnlock(): Promise<void> {
  if (!_sessionKey) return; // guard; never called locked
  let identities: IdentityRecord[];
  try {
    identities = await listIdentities();
  } catch {
    return;
  }
  for (const idRec of identities) {
    const fp = idRec.fingerprint;
    if (!_unlockVerifiedOwners.has(fp)) continue;
    try { await loadKey(fp); } catch (e) { console.warn('[enc-b] eager key migrate skipped', fp, e); }
    try { await loadPQKeys(fp); } catch (e) { console.warn('[enc-b] eager pq_keys migrate skipped', fp, e); }
    try { await loadVault(fp); } catch (e) { console.warn('[enc-b] eager vault migrate skipped', fp, e); }
    try { await loadShards(fp); } catch (e) { console.warn('[enc-b] eager shards migrate skipped', fp, e); }
  }
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
  // piece-2: the serialized device-mailbox keypair (secrets) — carried under includePrivateKeys so a
  // restore preserves onion mailbox continuity (no mailbox_fp churn on migration). Optional/absent on
  // pre-feature backups; a malformed value is skipped on import (a fresh mailbox inits on unlock).
  device_mailbox?: ReturnType<typeof serializeMailboxKeypair>;
  // task #714 R2a: the owner's GLOBAL delivery-receipt default, so a restore keeps it. Optional/absent on older backups (a restore then asks).
  // A plaintext file is untrusted: importAll accepts only 'off' from it. The passphrase-authenticated vault may carry any of the three.
  delivery_receipts_default?: DeliveryDefaultValue;
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
  // Only a record we could READ is exported; an absent or unreadable one is left out, never guessed.
  const delivery = await readDeliveryDefault(fingerprint);
  if (delivery.state === 'ok') backup.delivery_receipts_default = delivery.rec.value;

  if (includePrivateKeys) {
    backup.keys = await loadKey(fingerprint) ?? undefined;
    backup.pq_keys = await loadPQKeys(fingerprint) ?? undefined;
    backup.vault = await loadVault(fingerprint) ?? undefined;
    backup.shards = await loadShards(fingerprint) ?? undefined;
    // Device mailbox is a liveness nicety, not a launch-blocker — a corrupt one must NOT fail the
    // whole (critical-key) backup, so guard the read rather than letting a decrypt-fail throw propagate.
    try {
      const dmbKp = await loadDeviceMailbox(fingerprint);
      if (dmbKp) backup.device_mailbox = serializeMailboxKeypair(dmbKp);
    } catch (e) {
      console.warn('[export] device-mailbox skipped (present but unreadable)', e);
    }
  }

  return backup;
}

/**
 * Plaintext JSON backup is untrusted. Drop claimed trust / owner_verify / Gate
 * provenance so a crafted file cannot land Trusted, a fake verify mark, or a
 * Grow-Gate holding-room row. Persistence still goes through addContact
 * (fail-closed fingerprint↔key binding). Encrypted vault restore is unchanged.
 */
export function contactFromPlaintextBackup(
  raw: ContactRecord,
): Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'> {
  const next: Record<string, unknown> = { ...(raw as unknown as Record<string, unknown>) };
  delete next.id;
  delete next.added_at;
  delete next.owner_fingerprint;
  delete next.owner_verify;
  delete next.trusted;
  delete next.trusted_since;
  delete next.verified_at;
  delete next.grow_gate;
  delete next.grow_invite_nonce;
  delete next.grow_mint_channel;
  // An untrusted file may only TIGHTEN the delivery-receipt choice for a contact; 'on' (or anything else) is dropped.
  const dr = restrictOnly(next.delivery_receipts);
  if (dr) next.delivery_receipts = dr; else delete next.delivery_receipts;
  next.trust_level = 'known';
  next.verification = { method: 'none', verified_at: null };
  if (next.metadata && typeof next.metadata === 'object') {
    const meta = { ...(next.metadata as Record<string, unknown>) };
    delete meta.owner_verify;
    delete meta.grow_gate;
    delete meta.grow_invite_nonce;
    delete meta.grow_mint_channel;
    next.metadata = meta;
  }
  return next as Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'>;
}

export type PlaintextImportReport = {
  fingerprint: string;
  kept: number;
  skipped: number;
  /** Rows the device already held (the same contact from an earlier run, or one added since). Not added again, never overwritten. */
  alreadyPresent?: number;
  /** Existing rows whose block this restore SET because the backup had them blocked (it never clears one). */
  blockTightened?: number;
  /** The file's recovery-pieces record was not a usable set, so it was left out and the rest was restored, AND this device holds no record of its own after the import. The screen says so; this device does not know who holds the pieces. */
  shardsDropped?: true;
};

/** Owner-facing tally. Unbindable rows never persist; they are counted, not hidden. */
export function formatPlaintextImportReport(report: Pick<PlaintextImportReport, 'kept' | 'skipped'>): string {
  const known = `${report.kept} landed Known`;
  if (report.skipped <= 0) return known;
  return `${known}, ${report.skipped} skipped (key didn't match)`;
}

/**
 * Fail-closed identity binding for an untrusted plaintext backup. Refuse before any
 * IndexedDB write so a forged fingerprint leaves no partial state.
 */
export async function assertPlaintextBackupIdentityBinds(backup: SovereignBackup): Promise<string> {
  const fingerprint = (backup.identity?.identity?.fingerprint || '').trim();
  if (!fingerprint) throw new Error('Invalid backup: no fingerprint');
  const identityPub = backup.identity?.identity?.public_key || '';
  const identityPq = backup.identity?.post_quantum;
  if (!(await fingerprintMatchesKey(fingerprint, identityPub, {
    kem_public_key: identityPq?.kem_public_key,
    sig_public_key: identityPq?.sig_public_key,
  }))) {
    throw new Error(
      'fingerprint↔key binding failed — refusing to persist an identity whose fingerprint does not match its public key',
    );
  }
  return fingerprint;
}

/**
 * importAll cannot store imported keys without an unlocked passphrase session (they are encrypted at rest, never stored in the clear). Not a wrong-password
 * error: the file may have opened perfectly. Callers decide on `code`, never on the message text.
 */
export class PlaintextImportNeedsSession extends Error {
  readonly code = 'needs-device-passphrase' as const;
  constructor() { super('Set or enter your device passphrase before importing a plaintext backup — imported keys are encrypted at rest, never stored in the clear.'); this.name = 'PlaintextImportNeedsSession'; }
}

// DEVICE_PASSWORD_MIN lives in device-password.ts (pure) so the restore sentences read the same constant; it is re-exported here for every existing importer.
export { DEVICE_PASSWORD_MIN };

/**
 * A restore on a device with no session needs a password to protect the restored keys at rest, and neither the file's own password (absent, or shorter than
 * DEVICE_PASSWORD_MIN) nor a chosen one is usable. Thrown BEFORE any write; the screen asks for a new device password and tries again.
 */
export class DevicePasswordRequired extends Error {
  readonly code = 'needs-device-password' as const;
  constructor() { super(`Choose a device password of at least ${DEVICE_PASSWORD_MIN} characters before this backup is saved.`); this.name = 'DevicePasswordRequired'; }
}

/** The fields that say two KEYLESS contacts are the same row. Exact equality only: a near-duplicate is a new row, never a merge. */
const KEYLESS_MATCH_FIELDS = ['name', 'email', 'metadata'] as const;

function stableStringify(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

/** The block flag is not part of who a contact IS: a row blocked in the backup and the same row unblocked here are the same contact (the restore then tightens it). */
function withoutBlockFlag(metadata: unknown): unknown {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return metadata ?? null;
  const rest = { ...(metadata as Record<string, unknown>) };
  delete rest.blocked;
  return Object.keys(rest).length > 0 ? rest : null;
}

function keylessSignature(c: Record<string, unknown>): string {
  return stableStringify(KEYLESS_MATCH_FIELDS.map((f) => (f === 'metadata' ? withoutBlockFlag(c[f]) : c[f] ?? null)));
}

/** A block is kept in two places (c.blocked and c.metadata.blocked); a reader may check either. */
function isBlockedEither(c: Record<string, unknown>): boolean {
  const meta = c.metadata as Record<string, unknown> | null | undefined;
  return !!(c.blocked || (meta && typeof meta === 'object' && meta.blocked));
}

/**
 * Persist plaintext contacts via addContact. Unbindable rows skip and are counted.
 *
 * Safe to run again with the same file (a restore that stopped half way): a row the device already holds is counted `alreadyPresent`, not added a second time
 * and never overwritten. A KEYED row is already present when an existing row has its fingerprint. A KEYLESS row is matched as a MULTISET: each incoming row
 * consumes ONE identical existing row (exact equality on KEYLESS_MATCH_FIELDS), so two identical rows in the file come out as exactly two on the device.
 * A backup can only TIGHTEN a contact: when it says blocked and the existing row is not, both block fields are set; it never clears one.
 */
export async function importPlaintextContacts(
  ownerFingerprint: string,
  contacts: ContactRecord[] | undefined,
): Promise<{ kept: number; skipped: number; alreadyPresent: number; blockTightened: number }> {
  let kept = 0;
  let skipped = 0;
  let alreadyPresent = 0;
  let blockTightened = 0;
  const incoming = contacts || [];
  const existing: ContactRecord[] = incoming.length > 0 ? await getAllContacts(ownerFingerprint) : [];
  const byFingerprint = new Map<string, ContactRecord>();
  const keylessPool = new Map<string, ContactRecord[]>();
  for (const e of existing) {
    if (e.fingerprint && (e.public_key || '').trim()) byFingerprint.set(e.fingerprint, e);
    else {
      const sig = keylessSignature(e as Record<string, unknown>);
      keylessPool.set(sig, [...(keylessPool.get(sig) ?? []), e]);
    }
  }
  for (const contact of incoming) {
    try {
      const next = contactFromPlaintextBackup(contact) as Record<string, unknown>;
      const backupBlocked = isBlockedEither(contact as Record<string, unknown>);
      const keyed = !!((next.public_key as string) || '').trim();
      let match: ContactRecord | undefined;
      if (keyed) {
        match = byFingerprint.get(next.fingerprint as string);
      } else {
        const sig = keylessSignature(next);
        const pool = keylessPool.get(sig);
        if (pool && pool.length > 0) { match = pool.shift(); }
      }
      if (match) {
        if (backupBlocked && !(match.blocked && (match.metadata as Record<string, unknown> | undefined)?.blocked)) {
          const tightened = await updateContactIf(match.id, (ex) => ({ blocked: true, metadata: { ...((ex.metadata as object) || {}), blocked: true } }));
          if (tightened.applied) blockTightened++;
        }
        alreadyPresent++;
        continue;
      }
      if (backupBlocked) { next.blocked = true; next.metadata = { ...((next.metadata as object) || {}), blocked: true }; }
      await addContact(ownerFingerprint, next as Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'>);
      kept++;
    } catch (e) {
      // A row addContact refused is skipped and counted. A write that FAILED is not: it stops the restore, so the same file can be run again.
      if (!(e instanceof ContactRefused)) throw e;
      skipped++;
    }
  }
  return { kept, skipped, alreadyPresent, blockTightened };
}

export async function importAll(backup: SovereignBackup): Promise<PlaintextImportReport> {
  // 3a/block (Blocker-C, Archie #133842): a plaintext SovereignBackup carries no secret to derive
  // an at-rest key from, so refuse to import unless a passphrase session is already established
  // (the key stores are fail-closed). Block cleanly BEFORE any write — no partial import, no
  // plaintext-at-rest window.
  if (!isSessionUnlocked()) {
    throw new PlaintextImportNeedsSession();
  }
  const fingerprint = await assertPlaintextBackupIdentityBinds(backup);
  // The pieces record is stored as the file has it, so it is judged here with the other reads, before anything is written. One that is not a usable set is NOT stored, and the rest of the
  // backup still restores: the identity and keys matter more than a record of who holds the pieces. It is never silent when the device is left with no record: the report says so and the screen tells the person.
  const shardsUsable = !backup.shards || backupShardsProblem(backup.shards, fingerprint) === null;
  await assertRestoreKeepsOwnerDomain(fingerprint, '', 'keeps-open-session');

  await storeIdentity(fingerprint, backup.identity);
  // A restore: the choice is UNKNOWN on this device unless the file tightens it (a plaintext file may only say 'off').
  await writeDeliveryDefaultIfAbsent(fingerprint, restrictOnly(backup.delivery_receipts_default) === 'off' ? { v: 1, value: 'off' } : { v: 1, value: 'unknown' });

  if (backup.keys) {
    await storeKey(fingerprint, backup.keys.privateKey, backup.keys.passphrase);
  }
  if (backup.pq_keys) {
    await storePQKeys(fingerprint, backup.pq_keys);
  }
  if (backup.vault) {
    await storeVault(fingerprint, backup.vault);
  }
  if (backup.shards && shardsUsable) {
    await storeShards(fingerprint, backup.shards);
  }
  if (backup.device_mailbox) {
    // Validate the untrusted serialized shape BEFORE persisting — a malformed value would store fine
    // but fail every later decrypt (present-but-unreadable → ensure won't overwrite → a soft-lock). On
    // a bad shape, SILENTLY SKIP (this import region is log-free by invariant — skips surface via the
    // returned report, not console): a fresh mailbox inits on next unlock (under-reveal, fail-closed).
    // Only the SHAPE check may skip. A failed WRITE is a failed restore (it surfaces, and the same file can be run again); swallowing it would report
    // "restored" for a device that is missing its mailbox.
    let validShape = true;
    try {
      deserializeMailboxKeypair(backup.device_mailbox);
    } catch {
      validShape = false; /* malformed backup mailbox — skip; a fresh one inits on next unlock (fail-closed under-reveal) */
    }
    if (validShape) await storeDeviceMailbox(fingerprint, backup.device_mailbox);
  }

  // Same persistence gate as importVaultContents: never raw-put a contact from
  // an untrusted file. Unbindable rows skip; the identity import still completes.
  const { kept, skipped, alreadyPresent, blockTightened } = await importPlaintextContacts(fingerprint, backup.contacts);

  await setActiveFingerprint(fingerprint);
  // A record left out matters only if the device ends up with NO record of its own. Restoring onto a device that already holds a good one (the import is safe to run again) keeps it, and nothing was lost from this
  // device's view, so the screen says nothing. Read after every write; a record this device cannot read counts as none, and a failed read must not fail a restore that has already written.
  let shardsDropped = false;
  if (backup.shards && !shardsUsable) {
    try { shardsDropped = (await loadShards(fingerprint)) === null; } catch { shardsDropped = true; }
  }
  return { fingerprint, kept, skipped, alreadyPresent, blockTightened, ...(shardsDropped ? { shardsDropped: true as const } : {}) };
}

export type DeviceUnlock = 'already-open' | 'file-password' | 'new-password';

/**
 * Restore a backup on a device that may have no session yet. The order is the point: every check that only READS runs first, then the session key, then
 * importAll's writes, so a refusal leaves no salt and no session behind.
 *  1. the identity binds to its fingerprint;
 *  2. the restore stays in the owner's passphrase domain (every held key record opens with the password that will be used);
 *  3. the session key is set from: the open session (nothing to do) | the file's own password if it is at least DEVICE_PASSWORD_MIN | a chosen device password.
 *     A device that already holds this owner is never asked for a new password: the file's password must already open what is held.
 * A password shorter than the floor only OPENS the file; it never becomes the device password on a device that did not already use it.
 */
export async function importAllWithPassword(
  backup: SovereignBackup,
  opts: { filePassword?: string; devicePassword?: string } = {},
): Promise<PlaintextImportReport & { deviceUnlock: DeviceUnlock }> {
  const fingerprint = await assertPlaintextBackupIdentityBinds(backup);
  const filePassword = opts.filePassword ?? '';
  const devicePassword = opts.devicePassword ?? '';
  let use: string | null = null;
  let deviceUnlock: DeviceUnlock = 'already-open';
  if (!isSessionUnlocked()) {
    if (await deviceHoldsOwner(fingerprint)) {
      use = filePassword;
      deviceUnlock = 'file-password';
    } else if (filePassword.length >= DEVICE_PASSWORD_MIN) {
      use = filePassword;
      deviceUnlock = 'file-password';
    } else if (devicePassword.length >= DEVICE_PASSWORD_MIN) {
      use = devicePassword;
      deviceUnlock = 'new-password';
    } else {
      throw new DevicePasswordRequired();
    }
  }
  await assertRestoreKeepsOwnerDomain(fingerprint, use ?? '', 'keeps-open-session');
  if (use !== null) await initSessionKey(use);
  // The snapshot is taken after the session step (the device salt is an unlock parameter, not one of this owner's records) and BEFORE the first owner-record write.
  let before: OwnerSnapshot | null = null;
  try { before = await snapshotOwnerRows(fingerprint); } catch { before = null; }
  try {
    const report = await importAll(backup);
    return { ...report, deviceUnlock };
  } catch (err) {
    let after: OwnerSnapshot | null = null;
    try { after = await snapshotOwnerRows(fingerprint); } catch { after = null; }
    tagRestoreWrites(err, restoreWritesVerdict(before, after));
    throw err;
  }
}

/**
 * Persist an already-decrypted .svrnty VaultContents to IndexedDB — the
 * restore-onto-this-device / daily passphrase-unlock path. Converges to the SAME
 * at-rest state as genesis (browser-identity.ts) — encrypted — so a passphrase
 * restore STICKS across reload instead of only hydrating in-memory state (the
 * data-safety launch-blocker: before this, "Open Vault" set React state but wrote
 * nothing → reload = identity lost).
 *
 * AT-REST MODEL (2026-09-11 — Blocker-C fail-closed, Archie #133842): ALL key-material write
 * paths now converge to encrypted-at-rest or fail closed. genesis + this (importVaultContents) +
 * the passphrase-free recovery-code path (restoreIdentityFromSeedVault now requires a device
 * passphrase + initSessionKey before writing) + the encrypted-key import all establish a session
 * key first. The stores (storeKey/storePQKeys/storeVault/storeShards) THROW rather than ever
 * writing plaintext, so there is no plaintext-at-rest window — not even transiently. Plaintext
 * SovereignBackup import (importAll) blocks unless a session is established (no secret to derive
 * an at-rest key from).
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
  return (await importVaultContentsReport(contents, fingerprint)).fingerprint;
}

/** importVaultContents, plus what happened to the contacts: how many restored and which the store refused (named, with a plain reason). */
export async function importVaultContentsReport(
  contents: VaultContents,
  fingerprint: string,
): Promise<{ fingerprint: string; contacts: VaultContactsReport }> {
  const fp = (fingerprint || contents.identity?.identity?.fingerprint || '').trim();
  if (!fp) throw new Error('Invalid vault: no fingerprint');

  // Fail-closed identity binding (mirrors addContact): refuse a forged identity before
  // any write, so a rejected vault leaves NO partial state.
  const identityPub = contents.identity?.identity?.public_key || '';
  const identityPq = contents.identity?.post_quantum;
  if (!(await fingerprintMatchesKey(fp, identityPub, {
    kem_public_key: identityPq?.kem_public_key,
    sig_public_key: identityPq?.sig_public_key,
  }))) {
    throw new Error(
      'fingerprint↔key binding failed — refusing to persist an identity whose fingerprint does not match its public key',
    );
  }

  await storeIdentity(fp, contents.identity);
  // A restore: keep what the passphrase-authenticated vault carries (any of the three), else the choice is unknown here. Never overwrites a
  // record this device already holds.
  const carried = (contents.trustGraph as unknown as { delivery_receipts_default?: unknown } | null)?.delivery_receipts_default;
  const carriedParsed = parseDeliveryDefault({ v: 1, value: carried });
  await writeDeliveryDefaultIfAbsent(fp, { v: 1, value: carriedParsed.state === 'ok' ? carriedParsed.rec.value : 'unknown' });
  // The owner's suppression record and removed list ride the PASSPHRASE-AUTHENTICATED vault only (importAll, the plaintext path, never reads them). Strictly parsed and applied by tightening only:
  // a device with no record gets the carried persons and groups with global ON, and a backup's global-off waits for the person's confirmation. Best-effort (see restoreCarriedSuppression).
  await restoreCarriedSuppression(fp, (contents.trustGraph as unknown as { suppression?: unknown } | null)?.suppression, contents.sync?.lastModified);

  const classical = contents.keys?.classical;
  if (classical?.privateKey) {
    await storeKey(fp, classical.privateKey, classical.passphrase);
  }
  if (contents.keys?.pq) {
    await storePQKeys(fp, contents.keys.pq);
  }
  // #588: the beacon secret rides the backup (optional, additive; an old backup has none). Strictly validated, created only if none is held, and a bad or
  // failing record must never fail the restore.
  if (contents.keys?.beacon !== undefined) {
    try { await importBeaconKeyRecord(fp, contents.keys.beacon); } catch { /* best-effort: restore continues */ }
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
  const contactsReport = await restoreVaultContacts(contacts, (contact) => addContact(fp, contact));

  // The record, the removed list AND the book are now on this device; latch every person the record names and every removed id whose contact is NOT back in the book, BEFORE any
  // depositing path can run (a removed contact who is in the restored book follows Block / Trust, not the append-only list). Best-effort: a failure is repaired at the next unlock.
  await relatchBlocksForOwner(fp).catch(() => undefined);
  await setActiveFingerprint(fp);
  return { fingerprint: fp, contacts: contactsReport };
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

/** How a Grow code was minted. Legacy entries with no field normalize to remote (fail-closed). */
export type GrowMintChannel = 'in_person' | 'remote';

/** One issued code: when it stops accepting (epoch ms), which joiner fps it has accepted, and the
 *  per-code distinct-joiner cap (issuer-chosen at generation; default 1 = single-use). */
export interface IssuedCodeEntry {
  acceptUntil: number;
  accepted: string[];
  cap: number;
  channel: GrowMintChannel;
}
/** ownerFp -> { shortcode -> entry } */
export type IssuedCodeMap = Record<string, Record<string, IssuedCodeEntry>>;

function normalizeEntry(e: unknown): IssuedCodeEntry | null {
  if (!e || typeof e !== 'object') return null;
  const r = e as Record<string, unknown>;
  if (!Number.isFinite(r.acceptUntil as number)) return null;
  // cap: a legacy entry (pre-cap) defaults to 1 (single-use) — it must NOT retroactively become
  // multi-use. A present cap is clamped to [1, MAX].
  const cap = r.cap === undefined ? 1 : clampCodeCap(r.cap);
  const channel: GrowMintChannel = r.channel === 'in_person' ? 'in_person' : 'remote';
  return {
    acceptUntil: r.acceptUntil as number,
    accepted: Array.isArray(r.accepted) ? (r.accepted as string[]) : [],
    cap,
    channel,
  };
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

/** Pure: mint channel for a code. Missing / junk → remote (never upgrade to in-person). */
export function issuedCodeChannel(map: IssuedCodeMap, ownerFp: string, code: string): GrowMintChannel {
  return map?.[ownerFp]?.[code]?.channel === 'in_person' ? 'in_person' : 'remote';
}

/** Pure: distinct-joiner cap reached (in-person codes should regen after this). */
export function issuedCodeSpent(map: IssuedCodeMap, ownerFp: string, code: string): boolean {
  const e = map?.[ownerFp]?.[code];
  if (!e) return false;
  const cap = Number.isFinite(e.cap) ? e.cap : 1;
  return (Array.isArray(e.accepted) ? e.accepted.length : 0) >= cap;
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
 *  distinct-joiner cap (issuer-chosen at generation; default 1 = single-use, max 1000).
 *  In-person codes are forced cap 1. Omit `channel` to preserve a prior mint channel on cap edits. */
export async function recordIssuedGrowCode(
  ownerFp: string,
  code: string,
  cap: number = 1,
  channel?: GrowMintChannel,
): Promise<void> {
  if (!ownerFp || !code) return;
  const map = pruneIssuedCodes(await loadRawIssuedCodeMap(), Date.now());
  if (!map[ownerFp]) map[ownerFp] = {};
  const prior = map[ownerFp][code];
  const nextChannel: GrowMintChannel =
    channel === 'in_person' || channel === 'remote'
      ? channel
      : prior?.channel === 'in_person'
        ? 'in_person'
        : 'remote';
  // Fresh window on (re)issue; preserve any joiners already accepted on this code. In-person is
  // always single-use; remote cap is the issuer's choice, clamped to [1, 1000].
  map[ownerFp][code] = {
    acceptUntil: Date.now() + R1_ACCEPTANCE_WINDOW_MS,
    accepted: prior?.accepted ?? [],
    cap: nextChannel === 'in_person' ? 1 : clampCodeCap(cap),
    channel: nextChannel,
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

// ── Grow Gate arrivals (glass) ───────────────────────────────────────────────
// Remote (and in-person) joiners land here until the owner ADMITS them as Known.
// Not a contact yet — Galaxy / Contacts / PSI must not see them. The return-channel
// still consumes the mailbox and marks the issued code accepted (cap / single-use).
// Identity forge/restore "Gate" is a different machine (SoverentityFrontend).

const GROW_GATE_ARRIVALS_KEY = 'grow_gate_arrivals';

/** A solicited arrival waiting at the Gate — not yet a star. Owner-local only. */
export interface GateArrival {
  fingerprint: string;
  displayName: string;
  publicKeyArmored: string;
  pqSigPublicKey?: string;
  pqKemPublicKey?: string;
  /** The card's next_authority_commitment, kept only from a card whose signature verified. First write wins: see mergeArrivalPin (trust/grow-gate). */
  nextAuthorityCommitment?: string;
  epoch: number;
  inviteNonce: string;
  mintChannel: GrowMintChannel;
  arrivedAt: string;
  /** inbound_joiner = giver consumed a return-channel; scanned_giver = joiner gated the card they scanned. */
  direction: 'inbound_joiner' | 'scanned_giver';
}

/** ownerFp -> { peerFp -> arrival } */
export type GateArrivalMap = Record<string, Record<string, GateArrival>>;

function isGrowMintChannel(v: unknown): v is GrowMintChannel {
  return v === 'in_person' || v === 'remote';
}

export function normalizeArrival(raw: unknown): GateArrival | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.fingerprint !== 'string' || !r.fingerprint) return null;
  if (typeof r.publicKeyArmored !== 'string' || !r.publicKeyArmored) return null;
  if (typeof r.inviteNonce !== 'string' || !r.inviteNonce) return null;
  const epoch = Number.isSafeInteger(r.epoch) ? (r.epoch as number) : 0;
  const direction = r.direction === 'scanned_giver' ? 'scanned_giver' : 'inbound_joiner';
  const arrival: GateArrival = {
    fingerprint: r.fingerprint,
    displayName: typeof r.displayName === 'string' ? r.displayName : '',
    publicKeyArmored: r.publicKeyArmored,
    epoch,
    inviteNonce: r.inviteNonce,
    mintChannel: isGrowMintChannel(r.mintChannel) ? r.mintChannel : 'remote',
    arrivedAt: typeof r.arrivedAt === 'string' ? r.arrivedAt : new Date().toISOString(),
    direction,
  };
  if (typeof r.pqSigPublicKey === 'string' && r.pqSigPublicKey) arrival.pqSigPublicKey = r.pqSigPublicKey;
  if (typeof r.pqKemPublicKey === 'string' && r.pqKemPublicKey) arrival.pqKemPublicKey = r.pqKemPublicKey;
  const pin = canonicalAuthorityPin(r.nextAuthorityCommitment);
  if (pin) arrival.nextAuthorityCommitment = pin;
  return arrival;
}

async function loadRawGateMap(): Promise<GateArrivalMap> {
  const setting = await txGet<{ key: string; value: string }>('settings', GROW_GATE_ARRIVALS_KEY);
  if (!setting?.value) return {};
  try {
    const parsed = JSON.parse(setting.value);
    return parsed && typeof parsed === 'object' ? (parsed as GateArrivalMap) : {};
  } catch {
    return {};
  }
}

async function saveGateMap(map: GateArrivalMap): Promise<void> {
  await txPut('settings', { key: GROW_GATE_ARRIVALS_KEY, value: JSON.stringify(map) });
}

function normalizeGateMap(map: GateArrivalMap): GateArrivalMap {
  const out: GateArrivalMap = {};
  for (const [fp, bag] of Object.entries(map || {})) {
    const kept: Record<string, GateArrival> = {};
    for (const [peer, raw] of Object.entries(bag || {})) {
      const arrival = normalizeArrival(raw);
      if (arrival) kept[arrival.fingerprint || peer] = arrival;
    }
    if (Object.keys(kept).length > 0) out[fp] = kept;
  }
  return out;
}

/** Load Gate arrivals for one owner (not contacts — not on Galaxy). */
export async function loadGateArrivals(ownerFp: string): Promise<GateArrival[]> {
  if (!ownerFp) return [];
  const map = normalizeGateMap(await loadRawGateMap());
  const bag = map[ownerFp] || {};
  return Object.values(bag).sort((a, b) => (a.arrivedAt < b.arrivedAt ? 1 : -1));
}

export async function getGateArrival(ownerFp: string, peerFp: string): Promise<GateArrival | null> {
  if (!ownerFp || !peerFp) return null;
  const map = normalizeGateMap(await loadRawGateMap());
  return map[ownerFp]?.[peerFp] ?? null;
}

/** Idempotent by fingerprint: a retry overwrites the same arrival. */
export async function enqueueGateArrival(ownerFp: string, arrival: GateArrival): Promise<void> {
  if (!ownerFp) return;
  const normalized = normalizeArrival(arrival);
  if (!normalized) return;
  const map = normalizeGateMap(await loadRawGateMap());
  if (!map[ownerFp]) map[ownerFp] = {};
  map[ownerFp][normalized.fingerprint] = normalized;
  await saveGateMap(map);
}

export async function removeGateArrival(ownerFp: string, peerFp: string): Promise<void> {
  if (!ownerFp || !peerFp) return;
  const map = normalizeGateMap(await loadRawGateMap());
  if (!map[ownerFp]?.[peerFp]) return;
  delete map[ownerFp][peerFp];
  if (Object.keys(map[ownerFp]).length === 0) delete map[ownerFp];
  await saveGateMap(map);
}

// ── #822 (a) S1b: the IndexedDB glue under the beacon ports (DARK; nothing calls createBeaconPorts yet) ───────────────────────────────────────────
// beacon-ports.ts holds the rules (sealed, compare-and-swap, fail-closed) over two injected things; this block is those two things on the real database:
//  - the KV is rows of the `settings` store ({key, value: <string>}). A write is commitIfUnchanged, so the compare and the write happen in ONE
//    transaction; the row is compared by its JSON (no top-level enc_version), and `expected` is built in the same property order as the put.
//  - the sealer is the same AAD-bound AES path as the records above, keyed by the session key. A locked session THROWS (the store then cannot read or
//    write, and the latch reads 'removed'); a stored blob that does not open is an error, never "absent".
// Rows are `beacon_pair:<owner>:<pairId>` and `beacon_latch:<owner>:<pairId>:<kind>`; nothing else in this file enumerates the settings store.
async function txKeysWithPrefix(storeName: string, prefix: string): Promise<string[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).getAllKeys(IDBKeyRange.bound(prefix, `${prefix}\uffff`));
    request.onsuccess = () => resolve((request.result as IDBValidKey[]).filter((k): k is string => typeof k === 'string'));
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
    tx.onabort = () => { db.close(); reject(tx.error ?? new Error('transaction aborted')); };
  });
}

function beaconSettingsKV(): BeaconKV {
  return {
    async get(key) {
      const row = await txGet<{ key: string; value: unknown }>('settings', key);
      if (!row) return undefined;
      if (typeof row.value !== 'string') throw new Error('beacon kv: a stored row is not readable');
      return row.value;
    },
    async swap(key, expected, next) {
      return commitIfUnchanged(
        await openDB(),
        [{ store: 'settings', key, expected: expected === undefined ? null : { key, value: expected } }],
        [next === undefined ? { store: 'settings', delete: key } : { store: 'settings', value: { key, value: next } }],
      );
    },
    keys: (prefix) => txKeysWithPrefix('settings', prefix),
  };
}

function beaconSessionSealer(ownerFingerprint: string): Sealer {
  return {
    async seal(aad, value) {
      if (!_sessionKey) throw new Error('Session locked — refusing to store a beacon record unencrypted (fail-closed)');
      return JSON.stringify(await encryptContactRecord(_sessionKey, aad, ownerFingerprint, value));
    },
    async open(aad, blob) {
      if (!_sessionKey) throw new Error('beacon record unreadable: session locked');
      const payload = JSON.parse(blob) as { iv?: unknown; ciphertext?: unknown; enc_version?: number } | null;
      if (!payload || typeof payload.iv !== 'string' || typeof payload.ciphertext !== 'string') throw new Error('beacon record unreadable: malformed');
      return decryptContactRecord<unknown>(_sessionKey, aad, ownerFingerprint, { iv: payload.iv, ciphertext: payload.ciphertext, enc_version: payload.enc_version });
    },
  };
}

/** The two persistence ports createBeaconClient needs, over the app's IndexedDB, scoped to one owner. DARK: no caller yet. */
export function createBeaconPorts(ownerFingerprint: string): { store: BeaconStorePort; latch: LatchPort } {
  const kv = beaconSettingsKV();
  const sealer = beaconSessionSealer(ownerFingerprint);
  return { store: createBeaconStore(kv, sealer, ownerFingerprint), latch: createBeaconLatch(kv, sealer, ownerFingerprint) };
}
