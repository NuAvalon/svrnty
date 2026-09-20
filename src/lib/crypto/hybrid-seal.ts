// src/lib/crypto/hybrid-seal.ts
/**
 * Generic PQ-hybrid seal CORE — key-agnostic, domain-parameterized.
 *
 * The audited construction shared by note-seal (svrnty:note-seal:v1) and, going forward, beacon +
 * mailbox content (Flint #141587: "one core to review, consistent domain-sep"). Combines a classical
 * X25519 shared secret + an ML-KEM-1024 shared secret via HKDF-SHA256 into ONE AES-256-GCM key —
 * the TLS 1.3 hybrid / HPKE-style OR-secure combiner: safe if EITHER KEM holds, ONE AEAD op, both
 * KEMs + the transcript bound into the single key. NOT nested, NOT concat+MAC.
 *
 * KEY-AGNOSTIC BY DESIGN: this core takes the two shared secrets (ss_x25519, ss_mlkem) as INPUTS.
 * WHERE ss_x25519 comes from — the recipient's OpenPGP ENC subkey (X25519 ECDH) vs the Ed25519
 * identity key via toMontgomery — is the wrapper's job and a pinned crypto-contract decision (Flint).
 * The core bytes are identical either way, so it is verified once and reused.
 *
 * REJECT-CLASSICAL BY CONSTRUCTION: K folds in ss_mlkem, so a tampered/absent/downgraded PQ leg
 * yields the WRONG K → the GCM tag fails on open. There is no classical-only open path in this core.
 * (ML-KEM IND-CCA2 implicit-reject: a tampered kem_ct decaps to a pseudo-random ss_pq, does not throw.)
 *
 * Built byte-exact to a KAT vector (hybrid-seal.test.ts); Flint co-verifies combiner + AAD + domain-sep.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { uint8ToBase64, base64ToUint8 } from './pq.js';

const AES_KEY_LEN = 32;
const NONCE_LEN = 12;
const KEM_CT_LEN = 1568; // ML-KEM-1024 ciphertext
const X25519_LEN = 32;

/**
 * LP(x) = uint32_be(byteLen(x)) ‖ x — binary length-prefix / TLV framing.
 *
 * The SAME grammar Flint pinned for the rendezvous byte-pin (#141596): fixed-width big-endian length
 * makes every concatenation injective regardless of field contents (no delimiter 2nd-preimage). This is
 * the canonical home for the shared helper; trust-rendezvous.ts:130 will import it here (follow-up,
 * gated on Flint's ack — its output is byte-identical, re-proven by the byte-pin KATs).
 */
export function lpBin(x: Uint8Array): Uint8Array {
  const lp = new Uint8Array(4);
  new DataView(lp.buffer).setUint32(0, x.byteLength, false); // big-endian byte length
  return concatBytes(lp, x);
}

const u8 = (n: number): Uint8Array => Uint8Array.of(n & 0xff);

/**
 * K = HKDF-SHA256( IKM = ss_x25519 ‖ ss_mlkem ‖ epk ‖ kem_ct, salt = ∅,
 *                  info = LP(domain) ‖ LP(recipFp), L = 32 ).
 *
 * IKM = both shared secrets + the full KEM transcript (epk + kem_ct) → binding both encapsulations into
 * the key. info = domain (separation) + recipient fingerprint (a package for A can't open for B).
 */
export function deriveHybridSealKey(
  ssX: Uint8Array,
  ssPq: Uint8Array,
  epk: Uint8Array,
  kemCt: Uint8Array,
  domain: string,
  recipFp: string,
): Uint8Array {
  const ikm = concatBytes(ssX, ssPq, epk, kemCt);
  const info = concatBytes(lpBin(utf8ToBytes(domain)), lpBin(utf8ToBytes(recipFp)));
  return hkdf(sha256, ikm, undefined, info, AES_KEY_LEN);
}

/**
 * AAD = LP(u8 version) ‖ LP(domain) ‖ LP(recipFp) ‖ LP(senderFp) ‖ LP(kem_ct).
 *
 * Binds {version, domain, recipient fp, sender fp, ML-KEM ciphertext} into the AEAD (Flint #141587:
 * "AAD binds {version, recip-fp, sender-fp, mlkem-ct}"). Anti version/domain-downgrade, anti kem_ct
 * swap, anti sender-spoof-of-the-envelope (the inner note signature still authenticates content).
 */
export function buildHybridSealAAD(
  version: number,
  domain: string,
  recipFp: string,
  senderFp: string,
  kemCt: Uint8Array,
): Uint8Array {
  return concatBytes(
    lpBin(u8(version)),
    lpBin(utf8ToBytes(domain)),
    lpBin(utf8ToBytes(recipFp)),
    lpBin(utf8ToBytes(senderFp)),
    lpBin(kemCt),
  );
}

async function aesGcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    k,
    plaintext,
  );
  return new Uint8Array(ct); // ciphertext || 16B tag
}

async function aesGcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ctWithTag: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array | null> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      k,
      ctWithTag,
    );
    return new Uint8Array(pt);
  } catch {
    return null; // tag failure ⇒ REJECT (wrong ss_pq / tamper / wrong recipient / wrong domain)
  }
}

/** The opaque package that leaves the device. Only these fields hit the wire. */
export interface HybridSealPackage {
  v: number;
  /** domain-separation tag (e.g. "svrnty:note-seal:v1") — bound into K.info AND the AAD. */
  domain: string;
  recip_fp: string; // recipient identity fingerprint
  sender_fp: string; // sender identity fingerprint (authenticated by AAD; content by the inner sig)
  epk: string; // base64, 32B ephemeral X25519 public key
  kem_ct: string; // base64, 1568B ML-KEM-1024 ciphertext
  nonce: string; // base64, 12B GCM nonce
  ct: string; // base64, AES-256-GCM ciphertext || 16B tag
}

/**
 * Deterministic seal core — given ALL materials + nonce, produce the package. Byte-exact path the KAT
 * pins. Callers derive (ssX, ssPq, epk, kemCt) from the recipient keys + fresh randomness, then call this.
 */
export async function sealHybridWithMaterials(args: {
  plaintext: Uint8Array;
  ssX: Uint8Array;
  ssPq: Uint8Array;
  epk: Uint8Array;
  kemCt: Uint8Array;
  domain: string;
  recipFp: string;
  senderFp: string;
  nonce: Uint8Array;
  version?: number;
}): Promise<HybridSealPackage> {
  const version = args.version ?? 1;
  if (args.epk.length !== X25519_LEN) throw new Error(`epk must be ${X25519_LEN} bytes`);
  if (args.kemCt.length !== KEM_CT_LEN) throw new Error(`kem_ct must be ${KEM_CT_LEN} bytes`);
  if (args.nonce.length !== NONCE_LEN) throw new Error(`nonce must be ${NONCE_LEN} bytes`);
  const K = deriveHybridSealKey(args.ssX, args.ssPq, args.epk, args.kemCt, args.domain, args.recipFp);
  const aad = buildHybridSealAAD(version, args.domain, args.recipFp, args.senderFp, args.kemCt);
  const ct = await aesGcmSeal(K, args.nonce, args.plaintext, aad);
  return {
    v: version,
    domain: args.domain,
    recip_fp: args.recipFp,
    sender_fp: args.senderFp,
    epk: uint8ToBase64(args.epk),
    kem_ct: uint8ToBase64(args.kemCt),
    nonce: uint8ToBase64(args.nonce),
    ct: uint8ToBase64(ct),
  };
}

/**
 * OPEN core — given the package + the RECOMPUTED shared secrets (ssX from ECDH with pkg.epk, ssPq from
 * ML-KEM decap of pkg.kem_ct — both derived by the key-holding wrapper), return the plaintext or null.
 *
 * Rejects (null, never throws on attacker input): version/domain mismatch, wrong-recipient fp, malformed
 * fields, or AEAD tag failure (wrong ss_pq / tamper). Recipient check happens BEFORE any AEAD work.
 */
export async function openHybridWithMaterials(args: {
  pkg: HybridSealPackage;
  ssX: Uint8Array;
  ssPq: Uint8Array;
  myFp: string;
  expectDomain: string;
  expectVersion?: number;
}): Promise<Uint8Array | null> {
  const { pkg } = args;
  const expectVersion = args.expectVersion ?? 1;
  if (pkg.v !== expectVersion) return null;
  if (pkg.domain !== args.expectDomain) return null;
  if (pkg.recip_fp !== args.myFp) return null; // wrong recipient — reject before any crypto

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

  const K = deriveHybridSealKey(args.ssX, args.ssPq, epk, kemCt, pkg.domain, pkg.recip_fp);
  const aad = buildHybridSealAAD(pkg.v, pkg.domain, pkg.recip_fp, pkg.sender_fp, kemCt);
  return aesGcmOpen(K, nonce, ct, aad);
}
