// src/lib/crypto/mailbox-envelope.ts
/**
 * PQ-hybrid mailbox envelope — SEAL / OPEN.
 *
 * Implements Flint's Track A contract (shared/outbox/flint/pq_hybrid_mailbox_envelope_contract.md):
 * a message sealed TO a mailbox is hybrid-encapsulated — X25519(ephemeral) + ML-KEM-1024, combined
 * via HKDF-SHA256 into an AES-256-GCM key. The mailbox holds only the sealed package.
 *
 * REJECT-CLASSICAL BY CONSTRUCTION (not a runtime flag): K REQUIRES `ss_pq` from ML-KEM decap — there
 * is no classical-only decrypt path. A downgraded/absent PQ leg yields the wrong K → the GCM tag fails.
 * So "PQ-protected" is structurally true. `isPQEncapLive` flips WITH a real caller + e2e-green.
 *
 * Reuses LIVE primitives only — NO new crypto:
 *   - x25519 raw ECDH .............. @noble/curves/ed25519.js      (mutual-trust.ts:71)
 *   - ML-KEM-1024 encap/decap ...... ./pq (ml_kem1024, proven 12/12)
 *   - HKDF-SHA256 .................. @noble/hashes/hkdf.js          (hybrid.ts:228)
 *   - AES-256-GCM ................. WebCrypto crypto.subtle        (messaging/store.ts, crypto/recovery.ts)
 *
 * Built byte-exact to the contract §5 conformance vector; Flint co-verifies on commit (§6).
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { encapsulate, decapsulate, uint8ToBase64, base64ToUint8 } from './pq.js';

/** Exact algorithm tag bound into the AAD + package. Do not change without a version bump. */
export const MAILBOX_ENV_ALG = 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM';

const KDF_INFO_PREFIX = 'svrnty-mailbox-env-v1:';
const AAD_VERSION = 0x01;
const X25519_LEN = 32;
const KEM_CT_LEN = 1568;
const KEM_PUB_LEN = 1568;
const NONCE_LEN = 12;
const AES_KEY_LEN = 32;

/** The opaque package that leaves the device. Only these fields ever hit the wire / the mailbox. */
export interface MailboxEnvelopePackage {
  v: 1;
  alg: string;
  /** SHA256(x25519_pub || mlkem1024_pub) as 64 hex — the recipient mailbox identity. */
  mailbox_fp: string;
  epk: string; // base64, 32B ephemeral X25519 public key
  kem_ct: string; // base64, 1568B ML-KEM-1024 ciphertext
  nonce: string; // base64, 12B GCM nonce
  ct: string; // base64, AES-256-GCM ciphertext || 16B tag
}

export interface MailboxPublicKeys {
  x25519Pub: Uint8Array; // 32
  mlkem1024Pub: Uint8Array; // 1568
}

export interface MailboxSecretKeys {
  x25519Sec: Uint8Array; // 32
  mlkem1024Sec: Uint8Array; // 3168
}

/** mailbox_fp = SHA256( x25519_pub[32] || mlkem1024_pub[1568] ) → 64 hex. */
export function deriveMailboxFp(x25519Pub: Uint8Array, mlkem1024Pub: Uint8Array): string {
  if (x25519Pub.length !== X25519_LEN) throw new Error(`bad x25519 pub length ${x25519Pub.length}`);
  if (mlkem1024Pub.length !== KEM_PUB_LEN) throw new Error(`bad ml-kem pub length ${mlkem1024Pub.length}`);
  return bytesToHex(sha256(concatBytes(x25519Pub, mlkem1024Pub)));
}

/**
 * K = HKDF-SHA256( IKM = ss_c ‖ ss_pq ‖ epk ‖ kem_ct, salt = ∅, info = "svrnty-mailbox-env-v1:"‖mailbox_fp ).
 * Transcript-bound combiner — exported for the §5 conformance vector. `mailboxFpHex` enters info as its
 * hex string (per the vector), binding the recipient into the KDF.
 */
export function deriveEnvelopeKey(
  ssC: Uint8Array,
  ssPq: Uint8Array,
  epk: Uint8Array,
  kemCt: Uint8Array,
  mailboxFpHex: string,
): Uint8Array {
  const ikm = concatBytes(ssC, ssPq, epk, kemCt);
  const info = utf8ToBytes(KDF_INFO_PREFIX + mailboxFpHex);
  return hkdf(sha256, ikm, undefined, info, AES_KEY_LEN);
}

/**
 * AAD = 0x01 ‖ "|" ‖ ALG ‖ "|" ‖ mailbox_fp(raw32) ‖ "|" ‖ epk ‖ "|" ‖ kem_ct.
 * Binds version + recipient + BOTH ciphertexts into the AEAD (anti version-downgrade, anti cross-mailbox
 * replay, anti epk/kem_ct mix-and-match). `mailbox_fp` enters as RAW 32 bytes here (vs hex in the KDF info).
 */
export function buildEnvelopeAAD(mailboxFpHex: string, epk: Uint8Array, kemCt: Uint8Array): Uint8Array {
  const pipe = utf8ToBytes('|');
  return concatBytes(
    Uint8Array.of(AAD_VERSION),
    pipe,
    utf8ToBytes(MAILBOX_ENV_ALG),
    pipe,
    hexToBytes(mailboxFpHex),
    pipe,
    epk,
    pipe,
    kemCt,
  );
}

async function aesGcmSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    k,
    plaintext,
  );
  return new Uint8Array(ct); // ciphertext || 16B tag
}

async function aesGcmOpen(key: Uint8Array, nonce: Uint8Array, ctWithTag: Uint8Array, aad: Uint8Array): Promise<Uint8Array | null> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      k,
      ctWithTag,
    );
    return new Uint8Array(pt);
  } catch {
    return null; // tag failure ⇒ REJECT (wrong ss_pq / tamper / wrong recipient)
  }
}

/**
 * Deterministic seal core — given ALL key materials + nonce, produce the package. This is the byte-exact
 * path the §5 conformance vector pins. `sealToMailbox` wraps it with fresh ephemeral + encapsulation.
 * Exported for conformance testing; prefer `sealToMailbox` for real use (it generates fresh randomness).
 */
export async function sealWithMaterials(
  plaintext: Uint8Array,
  ssC: Uint8Array,
  ssPq: Uint8Array,
  epk: Uint8Array,
  kemCt: Uint8Array,
  mailboxFpHex: string,
  nonce: Uint8Array,
): Promise<MailboxEnvelopePackage> {
  const K = deriveEnvelopeKey(ssC, ssPq, epk, kemCt, mailboxFpHex);
  const aad = buildEnvelopeAAD(mailboxFpHex, epk, kemCt);
  const ct = await aesGcmSeal(K, nonce, plaintext, aad);
  return {
    v: 1,
    alg: MAILBOX_ENV_ALG,
    mailbox_fp: mailboxFpHex,
    epk: uint8ToBase64(epk),
    kem_ct: uint8ToBase64(kemCt),
    nonce: uint8ToBase64(nonce),
    ct: uint8ToBase64(ct),
  };
}

/**
 * SEAL a plaintext to a recipient mailbox. Fresh ephemeral X25519 + a fresh ML-KEM encapsulation per
 * call (K is per-message → GCM nonce-reuse across messages is structurally avoided). `mailboxFpHex` may
 * be supplied (from the registry) or derived from the pubkeys.
 */
export async function sealToMailbox(
  plaintext: Uint8Array,
  recipient: MailboxPublicKeys,
  mailboxFpHex?: string,
): Promise<MailboxEnvelopePackage> {
  if (recipient.x25519Pub.length !== X25519_LEN) throw new Error('recipient x25519 pub must be 32 bytes');
  if (recipient.mlkem1024Pub.length !== KEM_PUB_LEN) throw new Error('recipient ml-kem pub must be 1568 bytes');
  const mfp = mailboxFpHex ?? deriveMailboxFp(recipient.x25519Pub, recipient.mlkem1024Pub);

  const epkSk = x25519.utils.randomSecretKey();
  const epk = x25519.getPublicKey(epkSk);
  const ssC = x25519.getSharedSecret(epkSk, recipient.x25519Pub); // raw 32B; @noble throws on all-zero → fail closed
  const { ciphertext: kemCt, sharedSecret: ssPq } = encapsulate(recipient.mlkem1024Pub);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));

  return sealWithMaterials(plaintext, ssC, ssPq, epk, kemCt, mfp, nonce);
}

/**
 * OPEN a package with the recipient mailbox secrets. Returns the plaintext, or null on ANY rejection
 * (version/alg mismatch, wrong-recipient mailbox_fp, malformed field, or AEAD tag failure). Never throws
 * on attacker-controlled input.
 */
export async function openMailboxEnvelope(
  pkg: MailboxEnvelopePackage,
  secrets: MailboxSecretKeys,
  myMailboxFpHex: string,
): Promise<Uint8Array | null> {
  // Hostile relay input: a polled rendezvous blob can JSON.parse to null / a primitive. Guard before ANY
  // property access so the documented "never throws on attacker input" contract actually holds for the
  // consumers that don't wrap the open (resolveMailboxPointer, pollForPeerTrust). Surfaced by Flint's
  // null-not-throw invariant test (#141682): pkg="null" → JSON.parse → null → pkg.v used to throw.
  if (pkg === null || typeof pkg !== 'object') return null;
  if (pkg.v !== 1 || pkg.alg !== MAILBOX_ENV_ALG) return null;
  if (pkg.mailbox_fp !== myMailboxFpHex) return null; // wrong recipient — reject before any crypto

  let epk: Uint8Array, kemCt: Uint8Array, nonce: Uint8Array, ct: Uint8Array;
  try {
    epk = base64ToUint8(pkg.epk);
    kemCt = base64ToUint8(pkg.kem_ct);
    nonce = base64ToUint8(pkg.nonce);
    ct = base64ToUint8(pkg.ct);
  } catch {
    return null;
  }
  if (epk.length !== X25519_LEN || kemCt.length !== KEM_CT_LEN || nonce.length !== NONCE_LEN) return null;

  let ssC: Uint8Array;
  try {
    ssC = x25519.getSharedSecret(secrets.x25519Sec, epk); // reject on invalid point
  } catch {
    return null;
  }
  // IND-CCA2 implicit reject: a tampered kem_ct decaps to a PSEUDO-RANDOM ss_pq (does not throw) → wrong
  // K → the GCM tag fails below. This is the reject-classical / reject-tamper mechanism.
  const ssPq = decapsulate(kemCt, secrets.mlkem1024Sec);

  const K = deriveEnvelopeKey(ssC, ssPq, epk, kemCt, pkg.mailbox_fp);
  const aad = buildEnvelopeAAD(pkg.mailbox_fp, epk, kemCt);
  return aesGcmOpen(K, nonce, ct, aad);
}
