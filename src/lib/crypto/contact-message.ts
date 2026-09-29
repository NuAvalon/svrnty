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

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize } from '../format/canonical';
import { buildSignedBytes, SUITE_HYBRID } from '../crypto/sign-envelope';
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

interface InnerPayload {
  v: 1;
  from: string; // sender's claimed identity fingerprint
  msg: string;
  sig: string; // hybrid: hex(ed25519-sig 64B ‖ ML-DSA-87-sig)
}

// ── recipient-bound hybrid signature over the message ────────────────────────────────────────────
function contactMsgPreimage(message: string, recipientFp: string): Uint8Array {
  // Bind BOTH the message and WHO it is for → the recipient can't re-seal it to a third party as if sent to them.
  const canonical = canonicalize({ msg: message, to: normalizeFingerprintHex(recipientFp) });
  return utf8ToBytes(buildSignedBytes(DOMAIN_CONTACT_MSG, SUITE_HYBRID, canonical));
}

export function signContactMessage(message: string, recipientFp: string, signSeed: Uint8Array, sigSecret: Uint8Array): string {
  const p = contactMsgPreimage(message, recipientFp);
  return bytesToHex(concatBytes(ed25519.sign(p, signSeed), pqSign(p, sigSecret)));
}

export function verifyContactMessage(message: string, recipientFp: string, sigHex: string, senderSignPub: Uint8Array, senderSigPub: Uint8Array): boolean {
  try {
    const sig = hexToBytes(sigHex);
    if (sig.length <= AUTH_ED25519_SIG_BYTES) return false;
    const p = contactMsgPreimage(message, recipientFp);
    if (!ed25519.verify(sig.subarray(0, AUTH_ED25519_SIG_BYTES), p, senderSignPub)) return false;
    return pqVerify(p, sig.subarray(AUTH_ED25519_SIG_BYTES), senderSigPub);
  } catch {
    return false;
  }
}

// ── armor (copy-pasteable block) ──────────────────────────────────────────────────────────────────
function armor(pkg: MailboxEnvelopePackage): string {
  const body = uint8ToBase64(new TextEncoder().encode(JSON.stringify(pkg)));
  const wrapped = body.replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `${ARMOR_BEGIN}\n${wrapped}\n${ARMOR_END}`;
}
function dearmor(armored: string): MailboxEnvelopePackage | null {
  try {
    const s = (armored || '').trim();
    const b = s.indexOf(ARMOR_BEGIN);
    const e = s.indexOf(ARMOR_END);
    if (b === -1 || e === -1 || e <= b) return null;
    const body = s.slice(b + ARMOR_BEGIN.length, e).replace(/\s+/g, '');
    if (!body) return null;
    const pkg = JSON.parse(new TextDecoder().decode(base64ToUint8(body)));
    if (pkg === null || typeof pkg !== 'object') return null;
    return pkg as MailboxEnvelopePackage;
  } catch {
    return null;
  }
}

// ── core: sign-then-seal to a recipient's raw keys + identity fp (testable without OpenPGP) ─────────
export async function sealSignedToRecipient(
  message: string,
  recipient: { x25519Pub: Uint8Array; mlkem1024Pub: Uint8Array; fingerprint: string },
  sender: SenderKeys,
): Promise<string> {
  if (recipient.mlkem1024Pub.length !== KEM_PUB_LEN)
    throw new Error(`sealSignedToRecipient: kem pub must be ${KEM_PUB_LEN}B (ML-KEM-1024), got ${recipient.mlkem1024Pub.length}`);
  const sig = signContactMessage(message, recipient.fingerprint, sender.signSeed, sender.sigSecret);
  const inner: InnerPayload = { v: 1, from: normalizeFingerprintHex(sender.senderFingerprint), msg: message, sig };
  const pkg = await sealToMailbox(new TextEncoder().encode(JSON.stringify(inner)), {
    x25519Pub: recipient.x25519Pub,
    mlkem1024Pub: recipient.mlkem1024Pub,
  });
  return armor(pkg);
}

// ── high-level: encrypt to a CONTACT (extract recipient keys from the card, anti-poison) ────────────
/**
 * Authenticated-encrypt a message to a svrnty contact → armored copy-pasteable block. The sender signs
 * {msg, contact_fp} with their identity keys; only the contact can open it; the contact can then verify
 * the sender. Refuses if the card's keys don't hash to its claimed fingerprint (anti-poison).
 */
export async function encryptToContact(message: string, contact: ContactKeys, sender: SenderKeys): Promise<string> {
  const pubs = await canonicalPubsFromArmoredPublicKey(contact.public_key, contact.pq_kem_public_key, contact.pq_sig_public_key);
  if (contact.fingerprint && pubs.fingerprint !== normalizeFingerprintHex(contact.fingerprint))
    throw new Error('encryptToContact: contact keys do not match its claimed fingerprint — refusing to encrypt (anti-poison)');
  return sealSignedToRecipient(message, { x25519Pub: pubs.encPub, mlkem1024Pub: pubs.kemPub, fingerprint: pubs.fingerprint }, sender);
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
  const pkg = dearmor(armored);
  if (!pkg) return null;
  const myFp = deriveMailboxFp(me.x25519Pub, me.mlkem1024Pub);
  const pt = await openMailboxEnvelope(pkg, { x25519Sec: me.x25519Sec, mlkem1024Sec: me.mlkem1024Sec }, myFp);
  if (!pt) return null;

  let inner: InnerPayload;
  try {
    inner = JSON.parse(new TextDecoder().decode(pt));
    if (!inner || typeof inner.msg !== 'string' || typeof inner.from !== 'string' || typeof inner.sig !== 'string') return null;
  } catch {
    return null;
  }

  let senderVerified = false;
  if (senderCard) {
    try {
      const spubs = await canonicalPubsFromArmoredPublicKey(senderCard.public_key, senderCard.pq_kem_public_key, senderCard.pq_sig_public_key);
      // the provided card must BE the claimed sender (and match its own fingerprint if given), and its keys
      // must sign this message bound to ME.
      const cardIsClaimedSender = spubs.fingerprint === normalizeFingerprintHex(inner.from);
      const cardSelfConsistent = !senderCard.fingerprint || spubs.fingerprint === normalizeFingerprintHex(senderCard.fingerprint);
      senderVerified =
        cardIsClaimedSender &&
        cardSelfConsistent &&
        verifyContactMessage(inner.msg, me.myFingerprint, inner.sig, spubs.signPub, spubs.sigPub);
    } catch {
      senderVerified = false;
    }
  }
  return { message: inner.msg, senderVerified, senderFingerprint: inner.from };
}
