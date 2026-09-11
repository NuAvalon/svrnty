// src/lib/identity/contact-crypto.ts
// Per-contact encryption primitives (encryption-b) for the `contacts` store.
//
// Spec: Flint's per-contact-encryption crypto-seam rulings (2026-09-11) — the LOCKED seam.
// These are PURE functions (keys are passed in) so the crypto core can be co-verified and
// round-trip-tested in isolation. client-store.ts owns the session/index keys and wires these
// into addContact / getContact / the on-unlock migration.
//
// Seam (locked):
//  - Reuse the session AES-GCM key for record encryption — NO derived AES subkey (it is
//    non-extractable, so there are no bytes to HKDF; a shared passphrase root gives ~zero
//    marginal protection here). Cross-store confusion is prevented by the AAD domain label.
//  - Blinded keyed-PRF fingerprint index: idx = HMAC-SHA256(indexKey, fp). The real fingerprint
//    stays INSIDE the encrypted value; only the HMAC is the indexed field, so the contact graph
//    (the *set* of fingerprints) is not readable at rest — required once we claim
//    "relationships encrypted at rest" (a cleartext fp index would be a guard-that-lies).
//  - Per-record AES-GCM, random 12-byte IV, enc_version marker (mirrors encryptKeyData), + AAD
//    binding (scheme_version, "contacts", id, owner_fingerprint) so a ciphertext cannot be
//    transplanted across id / owner / store. AAD is an INJECTIVE length-prefixed TLV — never a
//    delimiter-join (a `|`-join is 2nd-preimage-forgeable under a boundary shift).

export const CONTACT_ENC_VERSION = 1;
const CONTACT_AAD_DOMAIN = 'svrnty/contacts/v1';
const DEFAULT_PBKDF2_ITERATIONS = 600_000; // matches client-store.ts deriveSessionKey

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
 * (Flint Q3.)
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
 * Encrypt a contact record's plaintext under the session key, bound to (id, owner) via AAD.
 * `sessionKey` = the existing non-extractable AES-GCM _sessionKey (reused, per Flint Q1).
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
 * `indexKey` = the non-extractable HMAC key (see deriveContactIndexKey); it is per-identity, so
 * idx values don't correlate across identities.
 */
export async function blindFingerprint(indexKey: CryptoKey, fingerprint: string): Promise<string> {
  const mac = new Uint8Array(
    await crypto.subtle.sign('HMAC', indexKey, new TextEncoder().encode(fingerprint)),
  );
  return toB64(mac);
}

/**
 * Derive the non-extractable HMAC index key from the passphrase.
 * Additive (a NEW key that does not touch the proven PBKDF2→AES session-key path — Flint Q2),
 * using a DISTINCT salt for domain separation from the AES session key.
 *
 * ⚠ CO-VERIFY (Flint): this is a second PBKDF2 pass, so it ~doubles unlock latency vs a single
 * derivation. Purely-additive per your Q2 ruling. Alternatives if the latency matters:
 *   (a) same-salt derive from the shared PBKDF2 output (key-reuse across AES+HMAC — mild smell),
 *   (b) one PBKDF2 → HKDF-master → {AES, HMAC} subkeys (clean + cheap, but refactors the AES path
 *       you deferred in Q1).
 * Chose the additive second-PBKDF2 to honor "don't touch the keys-AES path." Your call.
 */
export async function deriveContactIndexKey(
  passphrase: string,
  indexSalt: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: indexSalt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'HMAC', hash: 'SHA-256' },
    false, // non-extractable
    ['sign'],
  );
}
