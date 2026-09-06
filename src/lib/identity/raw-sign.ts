// Raw Ed25519 extract + auth-sign for identity/auth.
// The extract/sign pair below is copied verbatim from the greenfield identity spec
// (do not re-derive). Bind and PSI-auth preimage helpers sit underneath and only
// concatenate the specified UTF-8 strings.

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// svrnty identity = openpgp generateKey({type:'ecc',curve:'ed25519'}) → algo 22 (eddsaLegacy):
//   privateParams.seed = raw 32B Ed25519 seed; publicParams.Q = 33B (0x40 native-point prefix).
// PROVEN: noble.getPublicKey(seed) === strip0x40(Q) AND noble.sign(seed) verifies vs it.
const strip0x40 = (q: Uint8Array): Uint8Array =>
  (q.length === 33 && q[0] === 0x40) ? q.slice(1) : q;   // canonical 32B raw point

// key MUST be DECRYPTED first: await openpgp.decryptKey({ privateKey: readPrivateKey({armoredKey}), passphrase })
export function extractRawSign(decryptedIdentityKey: any): { seed: Uint8Array; signPub: Uint8Array } {
  const kp = decryptedIdentityKey.keyPacket;
  const seed: Uint8Array = kp.privateParams.seed;                       // 32B raw private — IN-MEMORY ONLY, never persist (it IS the vaulted openpgp key)
  const signPub = strip0x40(kp.publicParams.A ?? kp.publicParams.Q);    // 32B canonical Ed25519 pubkey
  // FAIL-CLOSED invariant — never sign with an inconsistent key:
  if (bytesToHex(ed25519.getPublicKey(seed)) !== bytesToHex(signPub))
    throw new Error('scalar-extract invariant failed: seed↔signPub mismatch');
  return { seed, signPub };
}

// raw Ed25519 auth-sign for tag#3 + /bind (raw 64B sig over EXACT preimage bytes)
export const rawSign = (preimage: Uint8Array, seed: Uint8Array): Uint8Array => ed25519.sign(preimage, seed);

/** 0x40-strip for algo-22 native-point prefixes (sign + enc pubkeys). */
export { strip0x40 };

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** /bind preimage: Ed25519(sign_seed, "svrnty-bind:{sign_pubkey_hex}:{nonce}:{epoch}") */
export function bindPreimage(signPubHex: string, nonce: string, epoch: string | number): Uint8Array {
  return utf8(`svrnty-bind:${signPubHex}:${nonce}:${epoch}`);
}

/** tag#3 PSI-auth preimage: Ed25519(sign_seed, "svrnty-psi-auth:{fp}:{unix}") */
export function psiAuthPreimage(fingerprint: string, unixSeconds: string | number): Uint8Array {
  return utf8(`svrnty-psi-auth:${fingerprint}:${unixSeconds}`);
}

export function signBind(
  seed: Uint8Array,
  signPubHex: string,
  nonce: string,
  epoch: string | number,
): Uint8Array {
  return rawSign(bindPreimage(signPubHex, nonce, epoch), seed);
}

export function signPsiAuth(
  seed: Uint8Array,
  fingerprint: string,
  unixSeconds: string | number,
): Uint8Array {
  return rawSign(psiAuthPreimage(fingerprint, unixSeconds), seed);
}

/**
 * PSI orchestrator currently signs utf8("{fp}:{unix}"). Prefix that wrapped
 * payload so the bytes under the signature are exactly svrnty-psi-auth:{fp}:{unix}.
 * If the orchestrator already passes the full preimage, sign it as-is.
 */
export function signPsiAuthWrapped(seed: Uint8Array, wrappedOrFull: Uint8Array): Uint8Array {
  const text = new TextDecoder().decode(wrappedOrFull);
  if (text.startsWith('svrnty-psi-auth:')) return rawSign(wrappedOrFull, seed);
  return rawSign(utf8(`svrnty-psi-auth:${text}`), seed);
}
