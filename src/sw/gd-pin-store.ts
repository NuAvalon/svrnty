// src/sw/gd-pin-store.ts
// Node Zero G-D — the pin store (§5 pin format P4). Persists, next to the Node Zero pin, the trust anchor the
// verifier follows: publisher_fp, the epoch-0 genesis pubkeys, the version-counter high-water-mark, and a
// diverged flag. Lives in IndexedDB (the only SW-durable store).
//
// INTEGRITY-BINDING (Flint amendment #141789): a bare IndexedDB record is JS-writable, so an in-origin XSS
// could silently overwrite the pin to an attacker lineage (Escalation B). Defence = the established pin is
// INTEGRITY-BOUND (a step-up/PRF-derived MAC over the record) so a direct overwrite can't forge a valid pin;
// and a deliberate RE-PIN requires a WebAuthn-PRF step-up (a script can fake a click, not a biometric).
// First-install CAPTURE stays TOFU (no PRF credential exists yet — chicken/egg).
//
// The PRF wrap-key is provided by a SEAM (getPinWrapKey), stub-not-live at launch — identical interface-
// decoupling to the item-3 guardian-wrap seam. Until the seam is live, the pin is stored with an
// authTag=null "honest-partial" marker (TOFU-integrity only); when the provider lands, records are MAC-bound
// and raw overwrites are rejected at read. No false-green: isPinIntegrityLive() reports the true state.

export interface PinRecord {
  publisherFpHex: string; // 64-hex = SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592)
  // genesis pubkeys (base64), epoch-0 signing keys = signPub/sigPub
  signPubB64: string; // ed25519 32
  encPubB64: string; // x25519 32
  kemPubB64: string; // ml-kem-1024 1568
  sigPubB64: string; // ml-dsa-87 2592
  hwm: number; // high-water-mark (starts 0)
  followedEpoch: 0; // launch epoch-0 only
  diverged: boolean; // set once a one-time "proceed anyway" ran a diverged bundle; persistent + visible
  acceptedBundleHashHex: string | null; // the currently-accepted served-bundle hash (for VERIFY-CURRENT fast path)
  // integrity: MAC over the record under the PRF wrap-key. null = honest-partial (seam not live / TOFU capture).
  authTag: string | null;
}

const DB_NAME = 'svrnty-nodezero';
const STORE = 'pin';
const KEY = 'nodezero'; // single-lineage pin at launch

// ── IndexedDB minimal wrapper (SW-safe; no external dep) ─────────────────────────────────────────────────
function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── PRF integrity seam (stub-not-live at launch; Flint delivers the provider) ────────────────────────────
export type PinWrapKeyProvider = (() => Promise<CryptoKey | null>) | null;
let _pinWrapProvider: PinWrapKeyProvider = null;

/** Wire the PRF wrap-key provider (Flint's, when it lands). Until then the pin is TOFU/honest-partial. */
export function setPinWrapKeyProvider(p: PinWrapKeyProvider): void {
  _pinWrapProvider = p;
}
/** True only once a real provider is wired — never claims integrity the storage can't back. */
export function isPinIntegrityLive(): boolean {
  return _pinWrapProvider !== null;
}

// The MAC'd fields (everything except authTag itself), stable-ordered → canonical bytes to MAC.
function macPreimage(r: Omit<PinRecord, 'authTag'>): string {
  return JSON.stringify([
    r.publisherFpHex, r.signPubB64, r.encPubB64, r.kemPubB64, r.sigPubB64,
    r.hwm, r.followedEpoch, r.diverged, r.acceptedBundleHashHex,
  ]);
}

async function computeAuthTag(r: Omit<PinRecord, 'authTag'>): Promise<string | null> {
  if (!_pinWrapProvider) return null; // honest-partial: no integrity binding yet
  const key = await _pinWrapProvider();
  if (!key) return null;
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(macPreimage(r)));
  return btoa(String.fromCharCode(...new Uint8Array(mac)));
}

// ── Public API ───────────────────────────────────────────────────────────────────────────────────────────

/**
 * Read the pin. Returns null if unset. If integrity is LIVE and the record's authTag does not validate, the
 * record is treated as FORGED (a raw IndexedDB overwrite) → returns null (fail-closed: no trusted pin), so the
 * verifier falls back to re-bootstrap/WARN rather than trusting an attacker-planted lineage.
 */
export async function readPin(): Promise<PinRecord | null> {
  const db = await openDb();
  const rec = await idbGet<PinRecord>(db, KEY);
  if (!rec) return null;
  if (isPinIntegrityLive()) {
    const { authTag, ...body } = rec;
    const expect = await computeAuthTag(body);
    if (!authTag || authTag !== expect) return null; // forged / overwritten → not a trusted pin
  }
  return rec;
}

/**
 * First-install TOFU capture. Only writes if NO pin exists (capture is one-shot; changing an established pin is
 * a step-up RE-PIN, not a capture). Returns false if a pin already exists.
 */
export async function capturePin(args: {
  publisherFpHex: string;
  signPubB64: string; encPubB64: string; kemPubB64: string; sigPubB64: string;
  firstCounter: number;
}): Promise<boolean> {
  const db = await openDb();
  const existing = await idbGet<PinRecord>(db, KEY);
  if (existing) return false; // never silently replace an established pin
  const body: Omit<PinRecord, 'authTag'> = {
    publisherFpHex: args.publisherFpHex,
    signPubB64: args.signPubB64, encPubB64: args.encPubB64, kemPubB64: args.kemPubB64, sigPubB64: args.sigPubB64,
    hwm: 0,
    followedEpoch: 0,
    diverged: false,
    acceptedBundleHashHex: null,
  };
  await idbPut(db, KEY, { ...body, authTag: await computeAuthTag(body) });
  return true;
}

/** Advance HWM + record the newly-accepted bundle hash (after a verified ADOPT-UPDATE). Re-MACs the record. */
export async function commitAccepted(hwm: number, acceptedBundleHashHex: string): Promise<void> {
  const cur = await readPin();
  if (!cur) throw new Error('commitAccepted: no pin');
  const { authTag, ...body } = { ...cur, hwm, acceptedBundleHashHex };
  const db = await openDb();
  await idbPut(db, KEY, { ...body, authTag: await computeAuthTag(body) });
}

/**
 * Mark the pin diverged (a one-time "proceed anyway" ran an unverified bundle). PERSISTENT + visible on every
 * open (§3 floor). This is NOT a re-pin — it never changes the anchor; the warning re-fires next load.
 */
export async function markDiverged(): Promise<void> {
  const cur = await readPin();
  if (!cur) return;
  const { authTag, ...body } = { ...cur, diverged: true };
  const db = await openDb();
  await idbPut(db, KEY, { ...body, authTag: await computeAuthTag(body) });
}
