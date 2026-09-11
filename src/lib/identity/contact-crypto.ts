// src/lib/identity/contact-crypto.ts
// Per-contact encryption primitives (encryption-b) for the `contacts` store.
//
// Spec: Flint's per-contact-encryption crypto-seam rulings (2026-09-11), as amended by his
// no-re-key correction ◆5701/◆5702 (KB#89159 — supersedes the original HKDF-master-derives-the-AES-key
// ruling ◆5699). These are PURE functions (keys are passed in) so the crypto core can be
// co-verified and round-trip-tested in isolation. client-store.ts owns the keys and wires these into
// addContact / getContact / the on-unlock migration.
//
// Seam (locked, per ◆5701/◆5702):
//  - AES: NO new record key. Contact records (and the PSI-A session store) REUSE client-store's
//    existing `_sessionKey` (direct-PBKDF2 AES-GCM). The identity stores (keys/pq_keys/vaults/shards)
//    stay under `_sessionKey` UNCHANGED — zero re-key, zero identity-lockout risk by construction.
//    Cross-store separation is by the AAD domain tag, not a separate key.
//  - KEY DERIVATION: ONE HKDF-master (a single 2nd PBKDF2 stretch, its own salt distinct from
//    key_encryption_salt → HKDF-Expand ×2) derives ONLY the two HMAC subkeys {index, manifest}.
//    Total unlock cost = 2× PBKDF2 (the existing AES-session + this HMAC-master), and STAYS 2×
//    regardless of how many HMAC subkeys. See deriveContactCryptoKeys.
//  - Per-record AES-GCM (reused _sessionKey), random 12-byte IV, enc_version marker, + AAD binding
//    (scheme_version, "contacts", id, owner_fingerprint) so a ciphertext can't be transplanted
//    across id / owner / store. AAD is an INJECTIVE length-prefixed TLV — never a delimiter-join
//    (a `|`-join is 2nd-preimage-forgeable under a boundary shift).
//  - Blinded keyed-PRF fingerprint index: idx = HMAC-SHA256(indexKey, fp). The real fingerprint
//    stays INSIDE the encrypted value; only the HMAC is the indexed field, so the contact graph
//    (the *set* of fingerprints) is not readable at rest — required once we claim
//    "relationships encrypted at rest" (a cleartext fp index would be a guard-that-lies).
//  - Book-integrity: an HMAC-authenticated manifest (manifest subkey) over {(id, version)…, count}
//    catches delete / rollback / truncation / reorder that per-record GCM tags miss.

export const CONTACT_ENC_VERSION = 1;
const CONTACT_AAD_DOMAIN = 'svrnty/contacts/v1';
const DEFAULT_PBKDF2_ITERATIONS = 600_000; // matches client-store.ts deriveSessionKey

// HKDF-Expand domain-separation labels — one per subkey. Frozen: changing a label re-derives that
// key (a migration event), so treat these as wire-freeze-class.
const HKDF_INFO = {
  index: 'svrnty/enc-b/index-key/v1',
  manifest: 'svrnty/enc-b/manifest-key/v1',
} as const;

// ── base64 (self-contained; mirrors client-store.ts toBase64/fromBase64) ──
function toB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Injective length-prefixed TLV encoding of the AAD fields.
 * Each field → [4-byte big-endian length][utf-8 bytes], concatenated in fixed order.
 * Injective (unlike a delimiter-join): distinct field-tuples always produce distinct byte
 * strings, even if a field could contain the delimiter — no boundary-shift 2nd-preimage.
 */
export function buildContactAAD(schemeVersion: number, id: string, ownerFingerprint: string): Uint8Array {
  const enc = new TextEncoder();
  const fields: Uint8Array[] = [
    enc.encode(String(schemeVersion)),
    enc.encode(CONTACT_AAD_DOMAIN),
    enc.encode(id),
    enc.encode(ownerFingerprint),
  ];
  let total = 0;
  for (const f of fields) total += 4 + f.length;
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const f of fields) {
    dv.setUint32(off, f.length, false); // big-endian length prefix
    off += 4;
    out.set(f, off);
    off += f.length;
  }
  return out;
}

export interface EncryptedContactPayload {
  enc_version: number;
  iv: string;         // base64, 12-byte AES-GCM nonce
  ciphertext: string; // base64, AES-GCM(plaintext JSON) authenticated with the AAD
}

/**
 * Encrypt a contact record's plaintext, bound to (id, owner) via AAD.
 * `sessionKey` = client-store's existing `_sessionKey` (the direct-PBKDF2 AES-GCM key that also
 * encrypts the identity stores) — REUSED per ◆5701, not a separate record key. The AAD domain tag
 * ('svrnty/contacts/v1') gives cross-store separation, so reuse is safe: a contacts ciphertext can't
 * be transplanted into another store because the recomputed AAD would differ and the GCM tag fails.
 */
export async function encryptContactRecord(
  sessionKey: CryptoKey,
  id: string,
  ownerFingerprint: string,
  plaintext: unknown,
): Promise<EncryptedContactPayload> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = buildContactAAD(CONTACT_ENC_VERSION, id, ownerFingerprint);
  const data = new TextEncoder().encode(JSON.stringify(plaintext));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, sessionKey, data),
  );
  return { enc_version: CONTACT_ENC_VERSION, iv: toB64(iv), ciphertext: toB64(ct) };
}

/**
 * Decrypt a contact payload. The AAD (id, owner) is recomputed and verified by the GCM tag —
 * a transplanted or tampered id/owner/store makes the tag verify fail (throws), so it can never
 * silently return the wrong record. `enc_version` from the stored payload selects the AAD scheme.
 */
export async function decryptContactRecord<T = unknown>(
  sessionKey: CryptoKey,
  id: string,
  ownerFingerprint: string,
  payload: { iv: string; ciphertext: string; enc_version?: number },
): Promise<T> {
  const iv = fromB64(payload.iv);
  const ct = fromB64(payload.ciphertext);
  const aad = buildContactAAD(payload.enc_version ?? CONTACT_ENC_VERSION, id, ownerFingerprint);
  const pt = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, sessionKey, ct),
  );
  return JSON.parse(new TextDecoder().decode(pt)) as T;
}

/**
 * Blinded keyed-PRF index value for a fingerprint: idx = HMAC-SHA256(indexKey, fp).
 * Deterministic → preserves O(1) getContactByFingerprint and the UNIQUE dedup constraint
 * (same fp → same idx) without decrypting, while hiding the raw fingerprint set at rest.
 * `indexKey` = the HKDF index subkey; it is per-identity, so idx values don't correlate across identities.
 */
export async function blindFingerprint(indexKey: CryptoKey, fingerprint: string): Promise<string> {
  const mac = new Uint8Array(
    await crypto.subtle.sign('HMAC', indexKey, new TextEncoder().encode(fingerprint)),
  );
  return toB64(mac);
}

// ── Book-integrity manifest (Q5) ──
// Per-record AES-GCM tags catch single-record corruption (bit-rot / partial write) but MISS
// book-level attacks: a DELETED record (no tag left to fail), a ROLLED-BACK/replayed old-but-valid
// ciphertext (its tag still verifies), TRUNCATION, REORDER. An HMAC-authenticated manifest over
// {(id, version)…, count} catches all four. HMAC — not a checksum (a local attacker with IndexedDB
// write can recompute a checksum; can't forge an HMAC without the unlocked key) — and not a full
// signature (non-repudiation buys nothing for local at-rest integrity). Manifest-MAC-fail → restore
// from cloud backup. The per-identity manifest subkey also prevents cross-owner manifest transplant,
// so no owner field is needed in the serialization.

export interface ManifestEntry {
  id: string;
  version: number;
}

/**
 * Injective canonical serialization of the manifest: entries sorted by id (so the MAC is independent
 * of store iteration order), each field length-prefixed, plus a domain tag and the total count.
 * A deleted / rolled-back / truncated / tampered book serializes differently → MAC verify fails.
 */
export function serializeManifest(entries: ManifestEntry[], count: number): Uint8Array {
  const sorted = [...entries].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const push = (bytes: Uint8Array) => {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    parts.push(len, bytes);
  };
  push(enc.encode('svrnty/contacts-manifest/v1'));
  push(enc.encode(String(count)));
  for (const e of sorted) {
    push(enc.encode(e.id));
    push(enc.encode(String(e.version)));
  }
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Compute the book-manifest MAC: HMAC-SHA256(manifestKey, serializeManifest(entries, count)). */
export async function computeManifestMAC(
  manifestKey: CryptoKey,
  entries: ManifestEntry[],
  count: number,
): Promise<string> {
  const mac = new Uint8Array(
    await crypto.subtle.sign('HMAC', manifestKey, serializeManifest(entries, count)),
  );
  return toB64(mac);
}

/**
 * Verify a stored manifest MAC (constant-time via crypto.subtle.verify).
 * Returns true iff the book (its id/version set + count) matches the authenticated manifest.
 */
export async function verifyManifestMAC(
  manifestKey: CryptoKey,
  entries: ManifestEntry[],
  count: number,
  storedMAC: string,
): Promise<boolean> {
  return crypto.subtle.verify('HMAC', manifestKey, fromB64(storedMAC), serializeManifest(entries, count));
}

// ── Key derivation: HKDF-master (one PBKDF2 → two HMAC subkeys) ──

export interface ContactCryptoKeys {
  // NO AES record key: contact-record AES reuses client-store's _sessionKey (◆5701). These are the
  // only two subkeys the HKDF-master derives.
  indexKey: CryptoKey;    // HMAC SHA-256, ['sign']          — blinded fingerprint index
  manifestKey: CryptoKey; // HMAC SHA-256, ['sign','verify'] — book-integrity manifest
}

/**
 * Derive the two non-extractable HMAC subkeys {index, manifest} from the passphrase via ONE
 * HKDF-master: a single PBKDF2 stretch → HKDF-Expand ×2 with distinct `info` labels. One expensive
 * PBKDF2; the two HKDF expansions are cheap, so this stays 2× total unlock cost (the existing
 * AES-session PBKDF2 + this one) no matter how many HMAC subkeys we add later.
 *
 * ◆5701/◆5702 (KB#89159): this HKDF-master derives ONLY the HMAC subkeys. It does NOT derive the
 * AES key — contact records reuse client-store's `_sessionKey`. So wiring this in does NOT re-key
 * any identity store; the "user can't decrypt their own identity" catastrophe is off the table by
 * construction. The migration shrinks to: encrypt contacts (new) + Blocker-C plaintext-fallback keys.
 *
 * `hmacMasterSalt` MUST be distinct from client-store's `key_encryption_salt` (the AES _sessionKey's
 * PBKDF2 salt) — domain separation between the AES key and the HMAC-master, so the two PBKDF2 outputs
 * are independent. Salt provenance is LOCKED (Flint, option b): the increment-2 client-store caller
 * derives it as SHA-256('svrnty/enc-b/hmac-master-salt/v1' ‖ key_encryption_salt) — distinct +
 * domain-separated, inherits key_encryption_salt's per-install randomness, no new loss-prone stored
 * state. A KDF salt needs uniqueness, not secrecy (passphrase already 600k-stretched).
 */
export async function deriveContactCryptoKeys(
  passphrase: string,
  hmacMasterSalt: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<ContactCryptoKeys> {
  // 1. PBKDF2 stretch (the single expensive step) → 256-bit HMAC-master.
  const pbkdf2Material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const masterBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hmacMasterSalt, iterations, hash: 'SHA-256' },
    pbkdf2Material,
    256,
  );
  // 2. Import the master as an HKDF key.
  const master = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveKey']);
  // 3. HKDF-Expand two domain-separated HMAC subkeys (cheap). The HKDF salt reuses the master salt;
  //    domain separation between index and manifest is provided by the distinct `info` labels.
  const enc = new TextEncoder();
  const expand = (info: string, usages: KeyUsage[]): Promise<CryptoKey> =>
    crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: hmacMasterSalt, info: enc.encode(info) },
      master,
      { name: 'HMAC', hash: 'SHA-256' },
      false, // non-extractable
      usages,
    );
  const [indexKey, manifestKey] = await Promise.all([
    expand(HKDF_INFO.index, ['sign']),
    expand(HKDF_INFO.manifest, ['sign', 'verify']),
  ]);
  return { indexKey, manifestKey };
}
