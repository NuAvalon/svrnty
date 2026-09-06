// src/lib/identity/fingerprint.ts
//
// Shared fingerprint↔key binding. Canonical identity id is
// hex(SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592)) — exact order, raw pubkey
// bytes, FIPS lengths. OpenPGP getFingerprint() is no longer minted as the
// identity id (greenfield). fingerprintMatchesKey (auth binding) is canonical-only
// (Res#1) — a 40-hex OpenPGP fingerprint no longer binds; only the paste/link helper
// bindPastedFingerprintToKey still derives a 40-hex fp for manual entry.

import { readKey } from 'openpgp';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { extractRawSign, strip0x40 } from './raw-sign';
import { sign as pqSign, verify as pqVerify, encapsulate as pqEncapsulate, decapsulate as pqDecapsulate } from '../crypto/pq';

export const SIGN_PUB_LEN = 32;
export const ENC_PUB_LEN = 32;
export const KEM_PUB_LEN = 1568;
export const SIG_PUB_LEN = 2592;

/** Lowercase hex only — strips spaces, colons, 0x, etc. */
export function normalizeFingerprintHex(raw: string): string {
  return (raw || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

function asU8(value: unknown, label: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value && typeof (value as { length?: unknown }).length === 'number') {
    return new Uint8Array(value as ArrayLike<number>);
  }
  throw new Error(`canonical fingerprint: ${label} is not bytes`);
}

function b64ToBytes(b64: string): Uint8Array | null {
  const s = (b64 || '').trim();
  if (!s) return null;
  try {
    if (typeof atob === 'function') {
      const binary = atob(s);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }
    return new Uint8Array(Buffer.from(s, 'base64'));
  } catch {
    return null;
  }
}

/**
 * SHA256(sign ‖ enc ‖ kem ‖ sig) as lowercase hex (64 chars).
 * Throws if any key is not the required FIPS length — never mint a truncated bundle.
 */
export function deriveCanonicalFingerprintHex(
  signPub: Uint8Array,
  encPub: Uint8Array,
  kemPub: Uint8Array,
  sigPub: Uint8Array,
): string {
  const sign = asU8(signPub, 'sign');
  const enc = asU8(encPub, 'enc');
  const kem = asU8(kemPub, 'kem');
  const sig = asU8(sigPub, 'sig');
  if (
    sign.length !== SIGN_PUB_LEN ||
    enc.length !== ENC_PUB_LEN ||
    kem.length !== KEM_PUB_LEN ||
    sig.length !== SIG_PUB_LEN
  ) {
    throw new Error('canonical fingerprint: a public key is not the required length');
  }
  const bundle = new Uint8Array(SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN + SIG_PUB_LEN);
  bundle.set(sign, 0);
  bundle.set(enc, SIGN_PUB_LEN);
  bundle.set(kem, SIGN_PUB_LEN + ENC_PUB_LEN);
  bundle.set(sig, SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN);
  return bytesToHex(sha256(bundle));
}

/** True iff claimed is the full 64-hex id or a prefix of at least 16 hex chars. */
export function canonicalClaimMatches(claimedHex: string, derived64: string): boolean {
  const claimed = normalizeFingerprintHex(claimedHex);
  const derived = normalizeFingerprintHex(derived64);
  if (!claimed || derived.length !== 64) return false;
  if (claimed === derived) return true;
  return claimed.length >= 16 && claimed.length <= 64 && derived.startsWith(claimed);
}

async function encPubFromOpenPgpKey(key: { getEncryptionKey?: () => Promise<any> }): Promise<Uint8Array> {
  if (typeof key.getEncryptionKey !== 'function') {
    throw new Error('canonical fingerprint: no encryption subkey');
  }
  const encKey = await key.getEncryptionKey();
  const q = encKey?.keyPacket?.publicParams?.Q ?? encKey?.keyPacket?.publicParams?.A;
  return strip0x40(asU8(q, 'enc'));
}

function signPubFromOpenPgpPublic(key: { keyPacket?: { publicParams?: { A?: unknown; Q?: unknown } } }): Uint8Array {
  const q = key.keyPacket?.publicParams?.A ?? key.keyPacket?.publicParams?.Q;
  return strip0x40(asU8(q, 'sign'));
}

/** Public halves used for fingerprint + satellite register. Never includes secrets. */
export type CanonicalPubs = {
  signPub: Uint8Array;
  encPub: Uint8Array;
  kemPub: Uint8Array;
  sigPub: Uint8Array;
  fingerprint: string;
};

export async function canonicalPubsFromArmoredPublicKey(
  armoredPublicKey: string,
  kemPublicKeyB64: string,
  sigPublicKeyB64: string,
): Promise<CanonicalPubs> {
  const key = await readKey({ armoredKey: armoredPublicKey });
  const signPub = signPubFromOpenPgpPublic(key);
  const encPub = await encPubFromOpenPgpKey(key);
  const kemPub = b64ToBytes(kemPublicKeyB64);
  const sigPub = b64ToBytes(sigPublicKeyB64);
  if (!kemPub || !sigPub) {
    throw new Error('canonical fingerprint: kem/sig public keys missing');
  }
  const fingerprint = deriveCanonicalFingerprintHex(signPub, encPub, kemPub, sigPub);
  return { signPub, encPub, kemPub, sigPub, fingerprint };
}

/**
 * Mint path: decrypted OpenPGP identity + already-generated kem/sig public bytes.
 * Uses scalar-extract for sign_pub (fail-closed seed↔pubkey check).
 */
export async function mintCanonicalFingerprint(args: {
  decryptedIdentityKey: any;
  kemPublicKey: Uint8Array;
  sigPublicKey: Uint8Array;
}): Promise<{ fingerprint: string; signPub: Uint8Array; encPub: Uint8Array }> {
  const { signPub } = extractRawSign(args.decryptedIdentityKey);
  const encPub = await encPubFromOpenPgpKey(args.decryptedIdentityKey);
  const fingerprint = deriveCanonicalFingerprintHex(
    signPub,
    encPub,
    args.kemPublicKey,
    args.sigPublicKey,
  );
  return { fingerprint, signPub, encPub };
}

// A fixed probe for the PQ pub↔secret correspondence round-trip (see reconstructCanonicalIdentityForRestore).
const RECON_PQ_PROBE = new TextEncoder().encode('svrnty-recovery-pqpub-correspondence-probe-v1');

/**
 * RESTORE path: reconstruct the CANONICAL identity id from recovered key material, WITHOUT trusting
 * any carried public fingerprint/key. Both restore adapters (seed-phrase + vault-passphrase) call this.
 *
 * Anti-poison (preserves the private-key↔fp bind against an untrusted .svrnty "import this vault" file):
 *   • sign+enc pubs are derived from the UNLOCKED private key (via mintCanonicalFingerprint), NOT any
 *     carried public — so a crafted vault can't substitute a foreign classical key.
 *   • the PQ public keys are proven to CORRESPOND to the recovered PQ secrets via a round-trip
 *     (ML-DSA sign→verify a probe; ML-KEM encap→decap) — @noble exposes no secret→public, so we
 *     verify correspondence rather than derive. A vault carrying self-consistent-but-non-matching PQ
 *     pubs fails the round-trip.
 * Then the recomputed canonical fp MUST equal the backup's claimed fp, or we refuse.
 * Throws (never silently downgrades to classical): legacy pre-PQ-pub backup → re-export guidance;
 * PQ pub↔secret mismatch → integrity error; fp mismatch → integrity error.
 */
export async function reconstructCanonicalIdentityForRestore(args: {
  decryptedIdentityKey: any;
  pqKemPublicKeyB64?: string;
  pqSigPublicKeyB64?: string;
  pqKemSecretKeyB64: string;
  pqSigSecretKeyB64: string;
  claimedFingerprint: string;
}): Promise<{
  fingerprint: string;
  post_quantum: { sig_algorithm: 'ML-DSA-87'; sig_public_key: string; kem_algorithm: 'ML-KEM-1024'; kem_public_key: string };
}> {
  // (0) Legacy: a pre-format-bump backup carries PQ secrets but NO PQ public keys. ML-DSA's public
  //     key is not derivable from its secret via @noble, so the canonical fp cannot be reconstructed.
  if (!args.pqKemPublicKeyB64 || !args.pqSigPublicKeyB64) {
    throw new Error(
      "This backup predates post-quantum recovery and can't be fully restored on this version. On a device where your identity is still unlocked, re-export your vault (Settings → Export) to create a current backup, then restore from that.",
    );
  }
  const kemPub = b64ToBytes(args.pqKemPublicKeyB64);
  const sigPub = b64ToBytes(args.pqSigPublicKeyB64);
  const kemSec = b64ToBytes(args.pqKemSecretKeyB64);
  const sigSec = b64ToBytes(args.pqSigSecretKeyB64);
  if (!kemPub || !sigPub || !kemSec || !sigSec) {
    throw new Error('This backup failed an integrity check (unreadable post-quantum key material) and was not restored.');
  }
  if (kemPub.length !== KEM_PUB_LEN || sigPub.length !== SIG_PUB_LEN) {
    throw new Error('This backup failed an integrity check (post-quantum key length does not match its identity) and was not restored.');
  }

  // (1) ANTI-POISON — prove the carried PQ public keys correspond to the recovered PQ secrets.
  //     ML-DSA: sign a fixed probe with the secret, verify with the claimed public.
  let sigOk = false;
  try { sigOk = pqVerify(RECON_PQ_PROBE, pqSign(RECON_PQ_PROBE, sigSec), sigPub); } catch { sigOk = false; }
  if (!sigOk) {
    throw new Error('This backup failed an integrity check (its post-quantum signing key does not match its identity) and was not restored.');
  }
  //     ML-KEM: encapsulate to the claimed public, decapsulate with the secret; shared secrets must match.
  let kemOk = false;
  try {
    const { ciphertext, sharedSecret } = pqEncapsulate(kemPub);
    const roundTrip = pqDecapsulate(ciphertext, kemSec);
    kemOk = sharedSecret.length === roundTrip.length && sharedSecret.every((b, i) => b === roundTrip[i]);
  } catch { kemOk = false; }
  if (!kemOk) {
    throw new Error('This backup failed an integrity check (its post-quantum encryption key does not match its identity) and was not restored.');
  }

  // (2) Reconstruct the canonical fp — sign+enc derived from the UNLOCKED private key (anti-poison),
  //     with the verified PQ pubs. Delegates to the vetted mint path.
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: args.decryptedIdentityKey,
    kemPublicKey: kemPub,
    sigPublicKey: sigPub,
  });

  // (3) The reconstructed canonical id MUST equal the backup's claimed fp, or refuse (never downgrade).
  if (fingerprint !== normalizeFingerprintHex(args.claimedFingerprint)) {
    throw new Error('This backup failed an integrity check (its key does not match its identity) and was not restored.');
  }

  return {
    fingerprint,
    post_quantum: {
      sig_algorithm: 'ML-DSA-87',
      sig_public_key: args.pqSigPublicKeyB64,
      kem_algorithm: 'ML-KEM-1024',
      kem_public_key: args.pqKemPublicKeyB64,
    },
  };
}

export type PqPublicOverlay = {
  kem_public_key?: string;
  sig_public_key?: string;
};

/**
 * True iff `publicKey` actually hashes to `claimedFingerprint`.
 * Returns false (never throws) on a mismatch, an unreadable key, or a missing input —
 * callers decide whether a false result is a hard refusal or a loud UI warning.
 *
 * Canonical-only (Res#1): kem+sig MUST be present at FIPS length and match the
 * four-key hash. The legacy 40-hex OpenPGP (SHA-1) basis is REMOVED — no pq → false.
 */
export async function fingerprintMatchesKey(
  claimedFingerprint: string,
  publicKey: string,
  pq?: PqPublicOverlay,
): Promise<boolean> {
  if (!claimedFingerprint || !publicKey) return false;
  const claimed = normalizeFingerprintHex(claimedFingerprint);
  if (!claimed) return false;

  const kem = b64ToBytes(pq?.kem_public_key || '');
  const sig = b64ToBytes(pq?.sig_public_key || '');
  // GATE (Res#1, greenfield): canonical-only. A valid identity MUST present PQ legs at
  // FIPS length and match the four-key hash. The legacy OpenPGP 40-hex (SHA-1) basis is
  // REMOVED — SHA-1 chosen-prefix collision = mint-time equivocation (one fp, two valid
  // bundles); un-retrofittable once real users mint. Zero real model-A users (Athena #130331).
  if (!(kem && sig && kem.length === KEM_PUB_LEN && sig.length === SIG_PUB_LEN)) {
    return false;
  }
  try {
    const pubs = await canonicalPubsFromArmoredPublicKey(
      publicKey,
      pq!.kem_public_key!,
      pq!.sig_public_key!,
    );
    return canonicalClaimMatches(claimed, pubs.fingerprint);
  } catch {
    return false; // unreadable key / length mismatch → binding cannot be established → refuse
  }
}

/**
 * Link / paste path: derive fingerprint from the armored public key and require the
 * pasted fingerprint to match (full 40 hex, or suffix ≥32 hex). Always returns the
 * DERIVED 40-char fingerprint — never the pasted string.
 *
 * Throws with honest UI copy on malformed key or mismatch.
 */
export async function bindPastedFingerprintToKey(
  pastedFingerprint: string,
  publicKey: string,
): Promise<string> {
  const pk = (publicKey || '').trim();
  if (!pk) {
    throw new Error('not a valid public key');
  }

  let derived: string;
  try {
    const key = await readKey({ armoredKey: pk });
    derived = normalizeFingerprintHex(key.getFingerprint());
  } catch {
    throw new Error('not a valid public key');
  }
  if (derived.length !== 40) {
    throw new Error('not a valid public key');
  }

  const pasted = normalizeFingerprintHex(pastedFingerprint);
  if (!pasted) {
    throw new Error('Paste their SVRNTY fingerprint and public key.');
  }

  const fullMatch = pasted === derived;
  const suffixOk =
    pasted.length >= 32 && pasted.length <= 40 && derived.endsWith(pasted);
  if (!fullMatch && !suffixOk) {
    throw new Error(
      'Fingerprint does not match this public key — paste the key that belongs to that fingerprint.',
    );
  }

  return derived;
}

/** Hex of the four public keys the satellite re-hashes to check the claimed fingerprint. */
export async function buildSatelliteRegisterFields(identity: {
  identity?: {
    fingerprint?: string;
    public_key?: string;
    name?: string;
  };
  post_quantum?: { kem_public_key?: string; sig_public_key?: string };
}): Promise<{
  fingerprint: string;
  public_key: string;
  name?: string;
  sign_pub: string;
  enc_pub: string;
  kem_pub: string;
  sig_pub: string;
} | null> {
  const fp = identity?.identity?.fingerprint;
  const publicKey = identity?.identity?.public_key;
  const kem = identity?.post_quantum?.kem_public_key;
  const sig = identity?.post_quantum?.sig_public_key;
  if (!fp || !publicKey || !kem || !sig) return null;
  try {
    const pubs = await canonicalPubsFromArmoredPublicKey(publicKey, kem, sig);
    return {
      fingerprint: pubs.fingerprint,
      public_key: publicKey,
      ...(identity.identity?.name ? { name: identity.identity.name } : {}),
      sign_pub: bytesToHex(pubs.signPub),
      enc_pub: bytesToHex(pubs.encPub),
      kem_pub: bytesToHex(pubs.kemPub),
      sig_pub: bytesToHex(pubs.sigPub),
    };
  } catch {
    return null;
  }
}
