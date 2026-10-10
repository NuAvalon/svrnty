// Raw Ed25519 extract + auth-sign for identity/auth.
// The extract/sign pair below is copied verbatim from the greenfield identity spec
// (do not re-derive). Bind and PSI-auth preimage helpers sit underneath and only
// concatenate the specified UTF-8 strings.

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
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

// svrnty identity enc subkey = openpgp ECDH curve25519 (algo 18): publicParams.Q = 33B (0x40 prefix),
// privateParams.d = 32B raw scalar in OpenPGP BIG-ENDIAN. @noble x25519 (RFC 7748) is LITTLE-ENDIAN, so the
// scalar must be REVERSED. PROVEN empirically: x25519.getPublicKey(reverse(d)) === strip0x40(Q) (byte-exact).
// Used to OPEN a PQ-hybrid contact message sealed to this identity's enc key (contact-message.ts).
// Key MUST be DECRYPTED first (openpgp.decryptKey). Async: the enc subkey is a subkey lookup.
export async function extractRawEnc(decryptedIdentityKey: any): Promise<{ encSec: Uint8Array; encPub: Uint8Array }> {
  const encSub = await decryptedIdentityKey.getEncryptionKey();
  const kp = encSub.keyPacket;
  const dBE: Uint8Array = kp.privateParams.d;                       // 32B OpenPGP big-endian scalar — IN-MEMORY ONLY
  if (!(dBE instanceof Uint8Array) || dBE.length !== 32) throw new Error('extractRawEnc: enc secret is not a 32B scalar');
  const encSec = Uint8Array.from([...dBE].reverse());              // → RFC 7748 little-endian for @noble x25519
  const encPub = strip0x40(kp.publicParams.Q ?? kp.publicParams.A); // 32B canonical x25519 pubkey
  // FAIL-CLOSED invariant — never decrypt with an inconsistent enc key (catches an encoding/endianness drift):
  if (bytesToHex(x25519.getPublicKey(encSec)) !== bytesToHex(encPub))
    throw new Error('scalar-extract invariant failed: enc secret↔encPub mismatch (endianness?)');
  return { encSec, encPub };
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
 * /allowed add|remove preimages (byte-exact to satellite.py _allowed_add_preimage :700 /
 * _allowed_remove_preimage :706). Signed by the BOUND sig key (self-bind model = the identity seed);
 * the satellite re-verifies vs the stored bound sig_pubkey and REQUIRES a bound identity (:815).
 * sender-bound so a generic psi-auth liveness sig can't be replayed onto /allowed, and the {add,remove}
 * domain-separation means an add sig can't authorize a remove (or vice-versa). All 3 fields are
 * `:`-free by validation (fps = lowercase-hex, unix = int) → injective, no delimiter-collision.
 */
export function allowedAddPreimage(ownerFp: string, senderFp: string, unixSeconds: string | number): Uint8Array {
  return utf8(`svrnty-allowed-add:${ownerFp}:${senderFp}:${unixSeconds}`);
}

export function allowedRemovePreimage(ownerFp: string, senderFp: string, unixSeconds: string | number): Uint8Array {
  return utf8(`svrnty-allowed-remove:${ownerFp}:${senderFp}:${unixSeconds}`);
}

export function signAllowedAdd(
  seed: Uint8Array,
  ownerFp: string,
  senderFp: string,
  unixSeconds: string | number,
): Uint8Array {
  return rawSign(allowedAddPreimage(ownerFp, senderFp, unixSeconds), seed);
}

export function signAllowedRemove(
  seed: Uint8Array,
  ownerFp: string,
  senderFp: string,
  unixSeconds: string | number,
): Uint8Array {
  return rawSign(allowedRemovePreimage(ownerFp, senderFp, unixSeconds), seed);
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

/**
 * allowed-sender-add preimage: Ed25519(sign_seed, "svrnty-allowed-add:{owner_fp}:{sender_fp}:{unix}").
 *
 * The sender-BOUND consent preimage for POST /allowed (KB#89666 hardening): binds owner + the sender
 * being consented + timestamp, so a live svrnty-psi-auth sig can't be replayed onto /allowed with an
 * attacker-chosen sender_fingerprint. It is a DISTINCT tag from svrnty-psi-auth — sign it with rawSign
 * DIRECTLY, NEVER through signPsiAuthWrapped (which would prepend svrnty-psi-auth: → wrong bytes).
 *
 * ✅ Flint-PINNED byte-exact (#138570): string + owner-then-sender order + no-wrap + fps are canonical
 * lowercase-hex (normalizeFingerprintHex). Client-sign here and satellite-verify (Athena's dedicated
 * _allowed_add_preimage) match these RAW utf-8 bytes. Callers MUST pass canonical fps.
 */
export function allowedAddPreimage(
  ownerFp: string,
  senderFp: string,
  unixSeconds: string | number,
): Uint8Array {
  return utf8(`svrnty-allowed-add:${ownerFp}:${senderFp}:${unixSeconds}`);
}

export function signAllowedAdd(
  seed: Uint8Array,
  ownerFp: string,
  senderFp: string,
  unixSeconds: string | number,
): Uint8Array {
  return rawSign(allowedAddPreimage(ownerFp, senderFp, unixSeconds), seed);
}

/**
 * allowed-sender-REMOVE preimage: Ed25519(sign_seed, "svrnty-allowed-remove:{owner_fp}:{sender_fp}:{unix}").
 *
 * The de-consent twin of allowedAddPreimage (Flint Q3, #138570) with a DISTINCT domain-tag so an add-sig
 * can never replay as a remove (or vice-versa). Same sender-binding + key axis (bound sig_pubkey) +
 * no-wrap + canonical-lowercase-hex fps. Transmitted as an X-Signature header "{unix}:{b64sig}" on
 * DELETE /allowed/{owner}, ±30s. PRIMITIVE ONLY — no client de-consent flow is wired yet; this matches
 * the satellite's hardened remove-verify (Athena, same pass #138583) so a future flow signs correctly.
 */
export function allowedRemovePreimage(
  ownerFp: string,
  senderFp: string,
  unixSeconds: string | number,
): Uint8Array {
  return utf8(`svrnty-allowed-remove:${ownerFp}:${senderFp}:${unixSeconds}`);
}

export function signAllowedRemove(
  seed: Uint8Array,
  ownerFp: string,
  senderFp: string,
  unixSeconds: string | number,
): Uint8Array {
  return rawSign(allowedRemovePreimage(ownerFp, senderFp, unixSeconds), seed);
}

/**
 * Mailbox-register preimage (KB#90104 item 3, byte-exact to satellite.py:1092):
 *   Ed25519(identity_seed, "svrnty-mailbox-reg-v1:{owner_identity_fp}:{mailbox_fp}:{epoch}")
 * GUARDRAIL (Flint): this `:`-joined string is injective ONLY because both fps are 64-lowercase-hex
 * (no ':' possible) and epoch is the trailing int. NEVER extend it with a variable-length or ':'-bearing
 * field — every FUTURE mutable-op preimage (rekey / relay-change / rehydrate) MUST be LP-framed instead.
 */
export function mailboxRegPreimage(
  ownerIdentityFp: string,
  mailboxFp: string,
  epoch: string | number,
): Uint8Array {
  return utf8(`svrnty-mailbox-reg-v1:${ownerIdentityFp}:${mailboxFp}:${epoch}`);
}

export function signMailboxReg(
  seed: Uint8Array,
  ownerIdentityFp: string,
  mailboxFp: string,
  epoch: string | number,
): Uint8Array {
  return rawSign(mailboxRegPreimage(ownerIdentityFp, mailboxFp, epoch), seed);
}
