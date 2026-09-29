// src/lib/crypto/contact-message.ts
//
// NO-WIRE PQ-hybrid message encrypt/decrypt to a svrnty CONTACT (Tier-1 dogfood — Peter #152422).
//
// A thin adapter over the CO-VERIFIED mailbox envelope (crypto/mailbox-envelope.ts): X25519(ephemeral)
// + ML-KEM-1024 → HKDF-SHA256 → AES-256-GCM, reject-classical-BY-CONSTRUCTION. NO new crypto is added
// here — this maps a contact's stored identity keys onto that seal and armors the result as a
// copy-pasteable block. NOTHING travels the wire: the armored block is handed over ANY channel
// (Telegram/email/paper) → zero relay metadata (structural sovereignty: nothing sent, nothing to observe).
//
// ML-KEM PARAMS = LENGTH-AS-SUITE: the contact's kem_pub must be 1568B (ML-KEM-1024); mailbox-envelope's
// sealToMailbox fails-closed on any other length, and we guard it explicitly here too — never hardcode a
// suite independent of the stored key (identity-card-sign.ts §6 downgrade-floor).

import { canonicalPubsFromArmoredPublicKey, KEM_PUB_LEN } from '../identity/fingerprint';
import { uint8ToBase64, base64ToUint8 } from './pq';
import {
  sealToMailbox,
  openMailboxEnvelope,
  deriveMailboxFp,
  type MailboxEnvelopePackage,
} from './mailbox-envelope';

const ARMOR_BEGIN = '-----BEGIN SVRNTY ENCRYPTED MESSAGE-----';
const ARMOR_END = '-----END SVRNTY ENCRYPTED MESSAGE-----';

/** A contact's public key material — every field is present on a valid signed identity card. */
export interface ContactEncryptKeys {
  /** OpenPGP armored public key — carries the classical x25519 encryption subkey. */
  public_key: string;
  /** base64 ML-KEM-1024 public key (1568B). */
  pq_kem_public_key: string;
  /** base64 ML-DSA-87 public key — used only to re-validate the card's fingerprint↔keys binding. */
  pq_sig_public_key: string;
  /** OPTIONAL: if given, the extracted keys MUST hash to it, or we refuse to encrypt (anti-poison). */
  fingerprint?: string;
}

/** My own identity key material needed to OPEN a message sealed to me. */
export interface MyDecryptKeys {
  x25519Sec: Uint8Array; // 32B x25519 encryption secret
  mlkem1024Sec: Uint8Array; // 3168B ML-KEM-1024 secret
  x25519Pub: Uint8Array; // 32B — to recompute my mailbox_fp (the recipient tag)
  mlkem1024Pub: Uint8Array; // 1568B
}

// ── armor (copy-pasteable block; the whole opaque package as one base64 body) ─────────────────────
function armor(pkg: MailboxEnvelopePackage): string {
  const body = uint8ToBase64(new TextEncoder().encode(JSON.stringify(pkg)));
  // 64-char wrapped lines for clean paste across channels that mangle long lines.
  const wrapped = body.replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `${ARMOR_BEGIN}\n${wrapped}\n${ARMOR_END}`;
}

/** Parse an armored block back to a package, or null on any malformation (never throws). */
function dearmor(armored: string): MailboxEnvelopePackage | null {
  try {
    const s = (armored || '').trim();
    const begin = s.indexOf(ARMOR_BEGIN);
    const end = s.indexOf(ARMOR_END);
    if (begin === -1 || end === -1 || end <= begin) return null;
    const body = s.slice(begin + ARMOR_BEGIN.length, end).replace(/\s+/g, '');
    if (!body) return null;
    const json = new TextDecoder().decode(base64ToUint8(body));
    const pkg = JSON.parse(json);
    if (pkg === null || typeof pkg !== 'object') return null;
    return pkg as MailboxEnvelopePackage;
  } catch {
    return null;
  }
}

// ── core: seal to raw recipient keys (testable without OpenPGP) ────────────────────────────────────
/**
 * Encrypt a UTF-8 message to a recipient's raw (x25519 enc, ML-KEM-1024) public keys → armored block.
 * Fails-closed on a wrong ML-KEM length (length-as-suite). No network, no sender identity required
 * (the classical leg is a fresh ephemeral X25519 inside the envelope).
 */
export async function encryptToRecipientKeys(
  message: string,
  x25519Pub: Uint8Array,
  mlkem1024Pub: Uint8Array,
): Promise<string> {
  if (mlkem1024Pub.length !== KEM_PUB_LEN)
    throw new Error(`encryptToRecipientKeys: kem pub must be ${KEM_PUB_LEN}B (ML-KEM-1024), got ${mlkem1024Pub.length}`);
  const pkg = await sealToMailbox(new TextEncoder().encode(message), { x25519Pub, mlkem1024Pub });
  return armor(pkg);
}

// ── high-level: encrypt to a CONTACT (extract keys from the card, anti-poison verify) ───────────────
/**
 * Encrypt a message to a svrnty contact → armored copy-pasteable block. Extracts the contact's x25519
 * enc pub + ML-KEM pub from their signed card (canonicalPubsFromArmoredPublicKey — the SAME validated
 * path register/verify use), and — if `fingerprint` is supplied — refuses unless the keys hash to it
 * (anti-poison: never encrypt to a card whose keys don't match its claimed identity).
 */
export async function encryptToContact(message: string, contact: ContactEncryptKeys): Promise<string> {
  const pubs = await canonicalPubsFromArmoredPublicKey(
    contact.public_key,
    contact.pq_kem_public_key,
    contact.pq_sig_public_key,
  );
  if (contact.fingerprint && pubs.fingerprint !== contact.fingerprint.toLowerCase())
    throw new Error('encryptToContact: contact keys do not match its claimed fingerprint — refusing to encrypt (anti-poison)');
  return encryptToRecipientKeys(message, pubs.encPub, pubs.kemPub);
}

// ── decrypt (open a block sealed to ME) ─────────────────────────────────────────────────────────────
/**
 * Decrypt an armored block that was sealed to MY identity keys → the UTF-8 message, or null on ANY
 * rejection (malformed block, wrong-recipient, tamper, or a downgraded/absent PQ leg — the GCM tag fails).
 * Never throws on attacker-controlled input.
 */
export async function decryptFromContact(armored: string, me: MyDecryptKeys): Promise<string | null> {
  const pkg = dearmor(armored);
  if (!pkg) return null;
  const myFp = deriveMailboxFp(me.x25519Pub, me.mlkem1024Pub);
  const pt = await openMailboxEnvelope(pkg, { x25519Sec: me.x25519Sec, mlkem1024Sec: me.mlkem1024Sec }, myFp);
  return pt ? new TextDecoder().decode(pt) : null;
}
