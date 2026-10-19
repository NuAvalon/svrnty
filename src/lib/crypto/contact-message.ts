// src/lib/crypto/contact-message.ts
//
// NO-WIRE, AUTHENTICATED PQ-hybrid message to a svrnty CONTACT (Tier-1 dogfood — Peter #152422).
//
// SIGN-THEN-SEAL (Archie #152480 / Vagus #152470 — a trust product needs authenticity, not just
// confidentiality): the sender signs {msg, recipient_fp} with their identity keys (hybrid ed25519 +
// ML-DSA-87), the recipient is BOUND into the signature (anti surreptitious-forwarding), and the inner
// {from, msg, sig} is sealed to the recipient with the CO-VERIFIED mailbox envelope (X25519 + ML-KEM-1024
// → HKDF-SHA256 → AES-256-GCM, Flint's Track-A, reject-classical-by-construction). NOTHING hits the wire —
// the armored block goes over any channel; the recipient verifies the sender AFTER opening.
//
// Reuses live primitives only — NO new crypto: mailbox-envelope (seal), sign-envelope (the byte-exact
// LP(domain)‖LP(suite)‖canonical preimage), ed25519 + pq(ML-DSA-87) signatures, canonicalPubsFromArmoredPublicKey.
//
// WIRE FORMAT v2 (task #556 — encoding-tax removal, ZERO crypto change): the armored block is a binary
// package (version+suite discriminator first, raw not-hex sig, single base64) instead of double-base64'd
// JSON. The signed PREIMAGE and the mailbox-envelope SEAL (KEM/KDF/AAD/AES-GCM) are byte-identical to v1 —
// only serialization changes. First decoded byte self-describes the format: 0x02 = binary v2, 0x7B ('{') =
// legacy v1 JSON (coexistence), anything else → reject-closed. The SUITE byte (0x01 HYBRID / 0x02 CLASSICAL)
// is bound into the signed preimage, so it cannot be downgraded. Lever-1 ships HYBRID (= v1 crypto, smaller
// bytes); lever-2 (CLASSICAL default for the one-shot) is a caller flag, Peter/Flint/Archie-gated.

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize } from '../format/canonical';
import { buildSignedBytes, SUITE_HYBRID, SUITE_CLASSICAL } from '../crypto/sign-envelope';
import { canonicalPubsFromArmoredPublicKey, KEM_PUB_LEN, AUTH_ED25519_SIG_BYTES, normalizeFingerprintHex } from '../identity/fingerprint';
import { sign as pqSign, verify as pqVerify, uint8ToBase64, base64ToUint8 } from './pq';
import { sealToMailbox, openMailboxEnvelope, deriveMailboxFp, type MailboxEnvelopePackage } from './mailbox-envelope';

const DOMAIN_CONTACT_MSG = 'svrnty:contact-msg:v1';
const ARMOR_BEGIN = '-----BEGIN SVRNTY ENCRYPTED MESSAGE-----';
const ARMOR_END = '-----END SVRNTY ENCRYPTED MESSAGE-----';

/** A contact's public key material (recipient OR the claimed sender) — from a signed identity card. */
export interface ContactKeys {
  public_key: string; // OpenPGP armored — carries the x25519 enc subkey + ed25519 sign key
  pq_kem_public_key: string; // base64 ML-KEM-1024 (1568B)
  pq_sig_public_key: string; // base64 ML-DSA-87 (2592B)
  fingerprint?: string; // if present, extracted keys MUST hash to it (anti-poison)
}

/** The SENDER's identity signing material (from their unlocked identity). */
export interface SenderKeys {
  signSeed: Uint8Array; // 32B ed25519 seed (extractRawSign.seed)
  sigSecret: Uint8Array; // ML-DSA-87 secret
  senderFingerprint: string; // the sender's identity id (64-hex)
}

/** MY identity material to OPEN + verify a message sealed to me. */
export interface MyKeys {
  x25519Sec: Uint8Array; // 32B x25519 enc secret (extractRawEnc.encSec)
  mlkem1024Sec: Uint8Array; // 3168B ML-KEM secret
  x25519Pub: Uint8Array; // 32B
  mlkem1024Pub: Uint8Array; // 1568B
  myFingerprint: string; // my identity id (64-hex) — the sig must be bound to this
}

export interface DecryptedMessage {
  message: string;
  /** true ONLY when a senderCard was supplied AND its keys sign the message bound to me. */
  senderVerified: boolean;
  /** the identity fingerprint the payload CLAIMS as sender (verify it against a known contact via `senderVerified`). */
  senderFingerprint: string;
}

// ── wire-format v2 constants + suite (task #556) ────────────────────────────────────────────────────
const WIRE_FORMAT_V2 = 0x02; // first byte of the de-armored binary blob
const INNER_FORMAT_V2 = 0x02; // first byte of the sealed plaintext
const LEGACY_JSON_LEAD = 0x7b; // '{' — a v1 armored package decodes to JSON (coexistence)
const SUITE_BYTE_HYBRID = 0x01; // ed25519 + ML-DSA-87 (default = v1 behavior)
const SUITE_BYTE_CLASSICAL = 0x02; // ed25519-only (lever-2, gated)

// Raw field lengths (mirror mailbox-envelope's internal constants; VALIDATED on decode).
const FP_RAW_LEN = 32;
const EPK_LEN = 32;
const KEM_CT_LEN = 1568;
const NONCE_LEN = 12;

/** Signature suite for the recipient-bound message sig. Bound into the signed preimage (anti-downgrade). */
export type ContactMsgSuite = 'hybrid' | 'classical';
function suiteId(s: ContactMsgSuite): string {
  return s === 'hybrid' ? SUITE_HYBRID : SUITE_CLASSICAL;
}
function suiteToByte(s: ContactMsgSuite): number {
  return s === 'hybrid' ? SUITE_BYTE_HYBRID : SUITE_BYTE_CLASSICAL;
}
function suiteFromByte(b: number): ContactMsgSuite | null {
  return b === SUITE_BYTE_HYBRID ? 'hybrid' : b === SUITE_BYTE_CLASSICAL ? 'classical' : null;
}

// ── recipient-bound signature over the message (suite bound into the preimage → anti-downgrade) ─────
function contactMsgPreimage(message: string, recipientFp: string, suite: ContactMsgSuite = 'hybrid'): Uint8Array {
  // Bind the message, WHO it is for, AND the suite → the recipient can't re-seal it to a third party as if
  // sent to them, and a classical-suite sig cannot be presented as hybrid or vice-versa (the suite is in the
  // signed bytes, so a downgrade flips the preimage → verify fails).
  const canonical = canonicalize({ msg: message, to: normalizeFingerprintHex(recipientFp) });
  return utf8ToBytes(buildSignedBytes(DOMAIN_CONTACT_MSG, suiteId(suite), canonical));
}

/** Raw recipient-bound signature bytes: HYBRID = ed25519(64B) ‖ ML-DSA-87; CLASSICAL = ed25519(64B) only. */
export function signContactMessageRaw(
  message: string,
  recipientFp: string,
  signSeed: Uint8Array,
  sigSecret: Uint8Array,
  suite: ContactMsgSuite = 'hybrid',
): Uint8Array {
  const p = contactMsgPreimage(message, recipientFp, suite);
  const ed = ed25519.sign(p, signSeed);
  return suite === 'hybrid' ? concatBytes(ed, pqSign(p, sigSecret)) : ed;
}

/** Hex form of the HYBRID signature — preserved byte-for-byte for the legacy v1 wire + hex-storing callers. */
export function signContactMessage(message: string, recipientFp: string, signSeed: Uint8Array, sigSecret: Uint8Array): string {
  return bytesToHex(signContactMessageRaw(message, recipientFp, signSeed, sigSecret, 'hybrid'));
}

/** Verify a raw recipient-bound signature under an explicit suite. */
export function verifyContactMessageRaw(
  message: string,
  recipientFp: string,
  sig: Uint8Array,
  suite: ContactMsgSuite,
  senderSignPub: Uint8Array,
  senderSigPub: Uint8Array,
): boolean {
  try {
    const p = contactMsgPreimage(message, recipientFp, suite);
    if (suite === 'hybrid') {
      if (sig.length <= AUTH_ED25519_SIG_BYTES) return false; // must carry a PQ half
      if (!ed25519.verify(sig.subarray(0, AUTH_ED25519_SIG_BYTES), p, senderSignPub)) return false;
      return pqVerify(p, sig.subarray(AUTH_ED25519_SIG_BYTES), senderSigPub);
    }
    if (sig.length !== AUTH_ED25519_SIG_BYTES) return false; // classical = exactly ed25519, no PQ half
    return ed25519.verify(sig, p, senderSignPub);
  } catch {
    return false;
  }
}

/** Hex form (HYBRID) — preserved for callers/tests on the legacy v1 path. */
export function verifyContactMessage(message: string, recipientFp: string, sigHex: string, senderSignPub: Uint8Array, senderSigPub: Uint8Array): boolean {
  try {
    return verifyContactMessageRaw(message, recipientFp, hexToBytes(sigHex), 'hybrid', senderSignPub, senderSigPub);
  } catch {
    return false;
  }
}

// ── binary wire primitives (u32_be length prefix — distinct from sign-envelope's netstring LP) ──────
function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}
function lp(x: Uint8Array): Uint8Array {
  return concatBytes(u32be(x.length), x);
}
/** A bounds-checked forward cursor. Underflow throws (callers wrap → null): never over-reads attacker bytes. */
function reader(buf: Uint8Array) {
  let off = 0;
  const need = (n: number) => {
    if (n < 0 || off + n > buf.length) throw new RangeError('wire underflow');
  };
  const u8 = () => {
    need(1);
    return buf[off++];
  };
  const take = (n: number) => {
    need(n);
    const s = buf.subarray(off, off + n);
    off += n;
    return s;
  };
  const u32 = () => {
    need(4);
    const v = buf[off] * 0x1000000 + ((buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]);
    off += 4;
    return v;
  };
  const lpf = () => take(u32());
  const rest = () => buf.length - off;
  return { u8, take, u32, lp: lpf, rest };
}

// ── inner (the SEALED plaintext): u8(0x02) ‖ from_fp(raw32) ‖ LP(sig_raw) ‖ LP(msg_utf8) ────────────
// Codec fns are exported for Flint's byte-exact co-verify vectors (§6/§6b) — pure, no secrets.
export function encodeInnerV2(fromFp: string, message: string, sigRaw: Uint8Array): Uint8Array {
  const from = hexToBytes(normalizeFingerprintHex(fromFp));
  if (from.length !== FP_RAW_LEN) throw new Error(`encodeInnerV2: from fp must be ${FP_RAW_LEN}B, got ${from.length}`);
  return concatBytes(Uint8Array.of(INNER_FORMAT_V2), from, lp(sigRaw), lp(utf8ToBytes(message)));
}
export function decodeInnerV2(bytes: Uint8Array): { from: string; msg: string; sig: Uint8Array } | null {
  try {
    const r = reader(bytes);
    if (r.u8() !== INNER_FORMAT_V2) return null;
    const from = bytesToHex(r.take(FP_RAW_LEN));
    const sig = r.lp();
    const msg = new TextDecoder().decode(r.lp());
    if (r.rest() !== 0) return null; // injective: no trailing bytes
    return { from, msg, sig };
  } catch {
    return null;
  }
}

// ── outer package: u8(0x02) ‖ u8(suite) ‖ LP(alg) ‖ mailbox_fp(raw32) ‖ epk(32) ‖ kem_ct(1568) ‖ nonce(12) ‖ LP(ct) ──
export function encodeOuterV2(suite: ContactMsgSuite, pkg: MailboxEnvelopePackage): Uint8Array {
  const mfp = hexToBytes(pkg.mailbox_fp);
  const epk = base64ToUint8(pkg.epk);
  const kemCt = base64ToUint8(pkg.kem_ct);
  const nonce = base64ToUint8(pkg.nonce);
  const ct = base64ToUint8(pkg.ct);
  if (mfp.length !== FP_RAW_LEN || epk.length !== EPK_LEN || kemCt.length !== KEM_CT_LEN || nonce.length !== NONCE_LEN)
    throw new Error('encodeOuterV2: fixed-length field size mismatch');
  return concatBytes(Uint8Array.of(WIRE_FORMAT_V2, suiteToByte(suite)), lp(utf8ToBytes(pkg.alg)), mfp, epk, kemCt, nonce, lp(ct));
}
export function decodeOuterV2(blob: Uint8Array): { suite: ContactMsgSuite; pkg: MailboxEnvelopePackage } | null {
  try {
    const r = reader(blob);
    if (r.u8() !== WIRE_FORMAT_V2) return null;
    const suite = suiteFromByte(r.u8());
    if (!suite) return null; // unknown suite → reject-closed (§6b-g)
    const alg = new TextDecoder().decode(r.lp());
    const mailbox_fp = bytesToHex(r.take(FP_RAW_LEN));
    const epk = uint8ToBase64(r.take(EPK_LEN));
    const kem_ct = uint8ToBase64(r.take(KEM_CT_LEN));
    const nonce = uint8ToBase64(r.take(NONCE_LEN));
    const ct = uint8ToBase64(r.lp());
    if (r.rest() !== 0) return null;
    return { suite, pkg: { v: 1, alg, mailbox_fp, epk, kem_ct, nonce, ct } };
  } catch {
    return null;
  }
}

// ── armor (copy-pasteable block) — single base64 over the binary package ────────────────────────────
function armorV2(suite: ContactMsgSuite, pkg: MailboxEnvelopePackage): string {
  const body = uint8ToBase64(encodeOuterV2(suite, pkg));
  const wrapped = body.replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `${ARMOR_BEGIN}\n${wrapped}\n${ARMOR_END}`;
}
function dearmorToBytes(armored: string): Uint8Array | null {
  try {
    const s = (armored || '').trim();
    const b = s.indexOf(ARMOR_BEGIN);
    const e = s.indexOf(ARMOR_END);
    if (b === -1 || e === -1 || e <= b) return null;
    const body = s.slice(b + ARMOR_BEGIN.length, e).replace(/\s+/g, '');
    if (!body) return null;
    return base64ToUint8(body);
  } catch {
    return null;
  }
}
// legacy v1 (JSON) coexistence — opens pre-#556 blocks so a rollout never silently drops a message.
function parseLegacyPackage(raw: Uint8Array): MailboxEnvelopePackage | null {
  try {
    const pkg = JSON.parse(new TextDecoder().decode(raw));
    if (pkg === null || typeof pkg !== 'object') return null;
    return pkg as MailboxEnvelopePackage;
  } catch {
    return null;
  }
}
function parseLegacyInner(pt: Uint8Array): { from: string; msg: string; sig: string } | null {
  try {
    const i = JSON.parse(new TextDecoder().decode(pt));
    if (!i || typeof i.msg !== 'string' || typeof i.from !== 'string' || typeof i.sig !== 'string') return null;
    return { from: i.from, msg: i.msg, sig: i.sig };
  } catch {
    return null;
  }
}

// ── core: sign-then-seal to a recipient's raw keys + identity fp (testable without OpenPGP) ─────────
export async function sealSignedToRecipient(
  message: string,
  recipient: { x25519Pub: Uint8Array; mlkem1024Pub: Uint8Array; fingerprint: string },
  sender: SenderKeys,
  suite: ContactMsgSuite = 'hybrid',
): Promise<string> {
  if (recipient.mlkem1024Pub.length !== KEM_PUB_LEN)
    throw new Error(`sealSignedToRecipient: kem pub must be ${KEM_PUB_LEN}B (ML-KEM-1024), got ${recipient.mlkem1024Pub.length}`);
  const sig = signContactMessageRaw(message, recipient.fingerprint, sender.signSeed, sender.sigSecret, suite);
  const inner = encodeInnerV2(sender.senderFingerprint, message, sig);
  const pkg = await sealToMailbox(inner, {
    x25519Pub: recipient.x25519Pub,
    mlkem1024Pub: recipient.mlkem1024Pub,
  });
  return armorV2(suite, pkg);
}

// ── high-level: encrypt to a CONTACT (extract recipient keys from the card, anti-poison) ────────────
/**
 * Authenticated-encrypt a message to a svrnty contact → armored copy-pasteable block. The sender signs
 * {msg, contact_fp} with their identity keys; only the contact can open it; the contact can then verify
 * the sender. Refuses if the card's keys don't hash to its claimed fingerprint (anti-poison).
 */
export async function encryptToContact(message: string, contact: ContactKeys, sender: SenderKeys, suite: ContactMsgSuite = 'hybrid'): Promise<string> {
  const pubs = await canonicalPubsFromArmoredPublicKey(contact.public_key, contact.pq_kem_public_key, contact.pq_sig_public_key);
  if (contact.fingerprint && pubs.fingerprint !== normalizeFingerprintHex(contact.fingerprint))
    throw new Error('encryptToContact: contact keys do not match its claimed fingerprint — refusing to encrypt (anti-poison)');
  return sealSignedToRecipient(message, { x25519Pub: pubs.encPub, mlkem1024Pub: pubs.kemPub, fingerprint: pubs.fingerprint }, sender, suite);
}

// ── decrypt + verify (open a block sealed to ME, then authenticate the sender) ──────────────────────
/**
 * Decrypt an armored block sealed to my identity keys, and — if `senderCard` is supplied — verify the
 * sender's signature (bound to ME). Returns { message, senderVerified, senderFingerprint }, or null on ANY
 * confidentiality-level rejection (malformed block, wrong-recipient, tamper, downgraded PQ leg). When no
 * senderCard is given (or it doesn't match/verify) the message still opens but senderVerified=false — the
 * UI MUST then show "sender NOT cryptographically verified".
 */
export async function decryptFromContact(armored: string, me: MyKeys, senderCard?: ContactKeys): Promise<DecryptedMessage | null> {
  const raw = dearmorToBytes(armored);
  if (!raw || raw.length === 0) return null;
  const myFp = deriveMailboxFp(me.x25519Pub, me.mlkem1024Pub);
  const secrets = { x25519Sec: me.x25519Sec, mlkem1024Sec: me.mlkem1024Sec };

  let from: string;
  let msg: string;
  let sig: Uint8Array;
  let suite: ContactMsgSuite;

  if (raw[0] === WIRE_FORMAT_V2) {
    const dec = decodeOuterV2(raw);
    if (!dec) return null; // malformed / unknown-suite → reject-closed
    const pt = await openMailboxEnvelope(dec.pkg, secrets, myFp);
    if (!pt) return null;
    const inner = decodeInnerV2(pt);
    if (!inner) return null;
    ({ from, msg, sig } = inner);
    suite = dec.suite;
  } else if (raw[0] === LEGACY_JSON_LEAD) {
    const pkg = parseLegacyPackage(raw);
    if (!pkg) return null;
    const pt = await openMailboxEnvelope(pkg, secrets, myFp);
    if (!pt) return null;
    const legacy = parseLegacyInner(pt);
    if (!legacy) return null;
    from = legacy.from;
    msg = legacy.msg;
    try {
      sig = hexToBytes(legacy.sig);
    } catch {
      sig = new Uint8Array(0); // bad hex → verify fails (length), message still opens unverified
    }
    suite = 'hybrid'; // v1 was always hybrid
  } else {
    return null; // unknown format version → reject-closed, never mis-decode
  }

  let senderVerified = false;
  if (senderCard) {
    try {
      const spubs = await canonicalPubsFromArmoredPublicKey(senderCard.public_key, senderCard.pq_kem_public_key, senderCard.pq_sig_public_key);
      // the provided card must BE the claimed sender (and match its own fingerprint if given), and its keys
      // must sign this message bound to ME. (fp↔key binding — the enforcement Flint's chaos #123 cites as
      // the reference the exchange path should mirror; preserved verbatim through the v2 refactor.)
      const cardIsClaimedSender = spubs.fingerprint === normalizeFingerprintHex(from);
      const cardSelfConsistent = !senderCard.fingerprint || spubs.fingerprint === normalizeFingerprintHex(senderCard.fingerprint);
      senderVerified =
        cardIsClaimedSender &&
        cardSelfConsistent &&
        verifyContactMessageRaw(msg, me.myFingerprint, sig, suite, spubs.signPub, spubs.sigPub);
    } catch {
      senderVerified = false;
    }
  }
  return { message: msg, senderVerified, senderFingerprint: from };
}
