// src/lib/identity/contact-crypto.ts
// Per-contact encryption primitives (encryption-b) for the `contacts` store.
//
// Spec: Flint's per-contact-encryption crypto-seam rulings (2026-09-11), as amended by the
// HKDF-master ruling (◆133623/133632 — supersedes the original "reuse _sessionKey / don't touch
// the AES path"). These are PURE functions (keys are passed in) so the crypto core can be
// co-verified and round-trip-tested in isolation. client-store.ts owns the derived keys and wires
// these into addContact / getContact / the on-unlock migration.
//
// Seam (locked):
//  - KEY DERIVATION: one PBKDF2 stretch → HKDF-Expand → three domain-separated NON-EXTRACTABLE
//    subkeys {AES-GCM record key, index HMAC key, manifest HMAC key}. One expensive PBKDF2, cheap
//    subkeys (avoids the 2nd/3rd-PBKDF2 latency of separate derivations). See deriveContactCryptoKeys.
//  - Per-record AES-GCM (record subkey), random 12-byte IV, enc_version marker, + AAD binding
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
  record: 'svrnty/enc-b/record-key/v1',
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
 * Encrypt a contact record's plaintext under the record subkey, bound to (id, owner) via AAD.
 * `recordKey` = the HKDF-derived AES-GCM record subkey (see deriveContactCryptoKeys).
 */
export async function encryptContactRecord(
  recordKey: CryptoKey,
  id: string,
  ownerFingerprint: string,
  plaintext: unknown,
): Promise<EncryptedContactPayload> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = buildContactAAD(CONTACT_ENC_VERSION, id, ownerFingerprint);
  const data = new TextEncoder().encode(JSON.stringify(plaintext));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, recordKey, data),
  );
  return { enc_version: CONTACT_ENC_VERSION, iv: toB64(iv), ciphertext: toB64(ct) };
}

/**
 * Decrypt a contact payload. The AAD (id, owner) is recomputed and verified by the GCM tag —
 * a transplanted or tampered id/owner/store makes the tag verify fail (throws), so it can never
 * silently return the wrong record. `enc_version` from the stored payload selects the AAD scheme.
 */
export async function decryptContactRecord<T = unknown>(
  recordKey: CryptoKey,
  id: string,
  ownerFingerprint: string,
  payload: { iv: string; ciphertext: string; enc_version?: number },
): Promise<T> {
  const iv = fromB64(payload.iv);
  const ct = fromB64(payload.ciphertext);
  const aad = buildContactAAD(payload.enc_version ?? CONTACT_ENC_VERSION, id, ownerFingerprint);
  const pt = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, recordKey, ct),
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

// ── Key derivation: HKDF-master (one PBKDF2 → three subkeys) ──

export interface ContactCryptoKeys {
  recordKey: CryptoKey;   // AES-GCM 256, ['encrypt','decrypt'] — per-record encryption
  indexKey: CryptoKey;    // HMAC SHA-256, ['sign']            — blinded fingerprint index
  manifestKey: CryptoKey; // HMAC SHA-256, ['sign','verify']   — book-integrity manifest
}

/**
 * Derive the three non-extractable subkeys from the passphrase via ONE PBKDF2 stretch + HKDF-Expand.
 *
 * PBKDF2(passphrase, salt, iters) → 256-bit master → import as HKDF → deriveKey ×3 with distinct
 * `info` labels (record / index / manifest). One expensive PBKDF2; the three HKDF expansions are
 * cheap. All subkeys are non-extractable. Domain separation is by the `info` label per Flint's
 * HKDF-master ruling (◆133623 — supersedes the earlier per-key 2nd/3rd-PBKDF2 approach, which would
 * have been 3× unlock latency).
 *
 * ⚠ MIGRATION (co-verify): the record subkey ≠ the current direct-PBKDF2 _sessionKey, so wiring this
 * in re-keys ALL existing stores (keys/pq_keys/vaults/shards + contacts) under the new subkey — done
 * once, folded into the Blocker-C on-unlock migration (one book-conversion). Handled in client-store
 * wiring, not here.
 */
export async function deriveContactCryptoKeys(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<ContactCryptoKeys> {
  // 1. PBKDF2 stretch (the single expensive step) → 256-bit master.
  const pbkdf2Material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const masterBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    pbkdf2Material,
    256,
  );
  // 2. Import the master as an HKDF key.
  const master = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveKey']);
  // 3. HKDF-Expand three domain-separated subkeys (cheap). HKDF salt reuses the PBKDF2 salt;
  //    domain separation is provided by the distinct `info` labels.
  const enc = new TextEncoder();
  const expand = (
    info: string,
    algo: AesKeyGenParams | HmacKeyGenParams,
    usages: KeyUsage[],
  ): Promise<CryptoKey> =>
    crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
      master,
      algo,
      false, // non-extractable
      usages,
    );
  const [recordKey, indexKey, manifestKey] = await Promise.all([
    expand(HKDF_INFO.record, { name: 'AES-GCM', length: 256 }, ['encrypt', 'decrypt']),
    expand(HKDF_INFO.index, { name: 'HMAC', hash: 'SHA-256' }, ['sign']),
    expand(HKDF_INFO.manifest, { name: 'HMAC', hash: 'SHA-256' }, ['sign', 'verify']),
  ]);
  return { recordKey, indexKey, manifestKey };
}
