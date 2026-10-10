// src/lib/crypto/contact-message-group.ts
//
// GROUP fan-out over the CO-VERIFIED single-recipient contact message (PR#155). NO new crypto:
// encrypting a message to N contacts = N INDEPENDENT recipient-bound sign-then-seals (encryptToContact
// looped), bundled into ONE copy-pasteable container. Each member opens ONLY their own block; the
// signature stays recipient-bound, so anti-forwarding is preserved per block (a member can't re-seal
// their block to a third party as if sent to them).
//
// The container carries ZERO security assumption — it is pure ROUTING. Tampering with it degrades to
// AVAILABILITY, never forgery/cross-decrypt: each block is an independent AEAD seal + recipient-bound
// hybrid signature. Drop a block → that member can't read (only); reorder → each finds its own;
// mislabel a block's `fp` → still fails closed (the real binding is the mailbox-fp inside the sealed
// AAD, not the container label) and decryptFromGroup falls back to trying every block.
//
// "KNOWN-group, not hidden-membership": the container exposes recipient count + fingerprints to any
// holder — the UI MUST label it honestly (a known recipient list, not a private group). A group-SCOPED
// envelope (shared group key, forward-within-group) is a DIFFERENT primitive that trades away
// anti-forwarding — deferred + gated on that tradeoff (Archie §0), build only on real need. — Apollo

import { uint8ToBase64, base64ToUint8 } from './pq';
import { normalizeFingerprintHex } from '../identity/fingerprint';
import {
  encryptToContact,
  decryptFromContact,
  type ContactKeys,
  type SenderKeys,
  type MyKeys,
  type DecryptedMessage,
} from './contact-message';

const ARMOR_BEGIN = '-----BEGIN SVRNTY ENCRYPTED GROUP MESSAGE-----';
const ARMOR_END = '-----END SVRNTY ENCRYPTED GROUP MESSAGE-----';

/** One recipient's independently-sealed block + an identity-fp ROUTING HINT (not a security field). */
interface GroupRecipientBlock {
  fp: string; // recipient's identity fingerprint (64-hex) — a fast-path label; real binding is the sealed AAD
  armored: string; // the per-recipient encryptToContact output (a complete, independently-sealed block)
}

interface GroupContainer {
  v: 1;
  recipients: GroupRecipientBlock[];
}

// ── armor (one copy-pasteable block for the whole group) ───────────────────────────────────────────
function armorGroup(c: GroupContainer): string {
  const body = uint8ToBase64(new TextEncoder().encode(JSON.stringify(c)));
  const wrapped = body.replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `${ARMOR_BEGIN}\n${wrapped}\n${ARMOR_END}`;
}

/** Parse + shape-validate a group container. Returns null on ANY malformation — never throws. */
function dearmorGroup(armored: string): GroupContainer | null {
  try {
    const s = (armored || '').trim();
    const b = s.indexOf(ARMOR_BEGIN);
    const e = s.indexOf(ARMOR_END);
    if (b === -1 || e === -1 || e <= b) return null;
    const body = s.slice(b + ARMOR_BEGIN.length, e).replace(/\s+/g, '');
    if (!body) return null;
    const c = JSON.parse(new TextDecoder().decode(base64ToUint8(body)));
    if (!c || typeof c !== 'object' || c.v !== 1 || !Array.isArray(c.recipients) || c.recipients.length === 0) return null;
    for (const r of c.recipients) {
      if (!r || typeof r.fp !== 'string' || typeof r.armored !== 'string') return null;
    }
    return c as GroupContainer;
  } catch {
    return null;
  }
}

/**
 * Encrypt ONE message to a GROUP of svrnty contacts → a single armored, copy-pasteable block.
 *
 * Fan-out: each contact gets an independent recipient-bound sign-then-seal via `encryptToContact`
 * (which anti-poison-checks every card). NO new crypto; anti-forwarding preserved per block. The group
 * is keyed on identity, so every contact MUST carry its `fingerprint`; duplicates are de-duped by it;
 * an empty group throws (nothing to encrypt to).
 */
export async function encryptToGroup(message: string, contacts: ContactKeys[], sender: SenderKeys): Promise<string> {
  if (!Array.isArray(contacts) || contacts.length === 0)
    throw new Error('encryptToGroup: a group needs at least one contact');

  // de-dup by identity fingerprint — never seal twice to the same member
  const seen = new Set<string>();
  const unique: ContactKeys[] = [];
  for (const c of contacts) {
    if (!c.fingerprint)
      throw new Error('encryptToGroup: every group contact must carry its fingerprint (the group is keyed on identity)');
    const fp = normalizeFingerprintHex(c.fingerprint);
    if (seen.has(fp)) continue;
    seen.add(fp);
    unique.push(c);
  }

  const recipients: GroupRecipientBlock[] = [];
  for (const c of unique) {
    const armored = await encryptToContact(message, c, sender); // per-contact anti-poison inherited
    recipients.push({ fp: normalizeFingerprintHex(c.fingerprint as string), armored });
  }
  return armorGroup({ v: 1, recipients });
}

/**
 * Open a group block sealed to ME + (optionally) verify the sender, exactly like `decryptFromContact`
 * but over the fan-out container. Tries the fingerprint-matched block FIRST (fast path), then EVERY
 * block (robust — a mislabeled container still opens for its true recipient). A block not sealed to me
 * returns null from `decryptFromContact` (wrong-recipient), so this never leaks another member's
 * plaintext. Returns the DecryptedMessage, or null (not a member / malformed / tampered-to-me).
 */
export async function decryptFromGroup(
  armored: string,
  me: MyKeys,
  senderCard?: ContactKeys,
): Promise<DecryptedMessage | null> {
  const c = dearmorGroup(armored);
  if (!c) return null;
  const myFp = normalizeFingerprintHex(me.myFingerprint);
  const ordered = [
    ...c.recipients.filter((r) => normalizeFingerprintHex(r.fp) === myFp),
    ...c.recipients.filter((r) => normalizeFingerprintHex(r.fp) !== myFp),
  ];
  for (const r of ordered) {
    const out = await decryptFromContact(r.armored, me, senderCard);
    if (out) return out;
  }
  return null;
}
