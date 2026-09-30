// src/lib/crypto/onion-envelope.ts
/**
 * Onion-blinded two-shell mailbox delivery — the #558 keystone primitive (K0).
 *
 * ONE primitive: `sealToMailbox` nested TWICE. NO new crypto core — pure composition of the co-verified
 * PQ-hybrid mailbox envelope (mailbox-envelope.ts, Flint Track A §5/§6).
 *
 *   INNER = sealToMailbox(content, recipient DEVICE keys)   // content; the satellite never reads it
 *   OUTER = sealOnion(INNER, satellite keys, route)         // routing shell; the satellite peels it
 *
 * The satellite peels the OUTER with its OWN keypair (peelOnion) → learns only the routing datum + a
 * FINGERPRINT-STRIPPED inner (per-message-fresh fields only). It CANNOT read the content (INNER is sealed
 * to the DEVICE, not the satellite) AND it CANNOT link the recipient (see K0-1 below). This is the two-
 * keypair separation the keystone rests on (spec §2/§3): satellite keypair ≠ device keypair.
 *
 * ★ K0-1 BLINDING (Flint gate, KB#91389) — the load-bearing property: a MailboxEnvelopePackage carries a
 * cleartext `mailbox_fp = SHA256(device pubkeys)`, which is the ONLY STABLE field (epk/kem_ct/nonce/ct are
 * per-message fresh). If it rode through the peel, a hosted satellite would link ALL of a recipient's
 * traffic across time + senders → zero relay-unlinkability. So sealOnion STRIPS `mailbox_fp` from the
 * inner on the wire; the recipient DEVICE re-supplies its own fp at open time (openOnionInner) — the KDF
 * info + AAD + recipient-check inside openMailboxEnvelope all use the passed `myMailboxFpHex`, so the
 * round-trip is byte-identical. Routing is by the bucket/`route`, never by a wire fp.
 *
 * K0 SCOPE = this client-side nest/peel primitive. The satellite keypair generation/hosting + the
 * server-side peel/route wiring are separate (a server keypair module + the external satellite service).
 * The blinded, rotating `route` id is K1 (§5 ratchet); here `route` is an opaque passthrough string.
 *
 * Footgun-B (KB#91308): sealOnion NEVER supplies the outer mailbox_fp — it is derived from the satellite
 * pubkeys inside sealToMailbox (no fp arg). (Full removal of the legacy optional param on sealToMailbox
 * itself is tracked in M6, not this PR.)
 *
 * NOT handled here (later nodes): type-opacity / size-padding / uniform framing so a peeling satellite
 * can't classify distress-vs-consent-vs-message are §8 / K3 (Flint Finding-#1 + cover-traffic). Tighter
 * binary wire (drop JSON) is the M6 wire-format pass (Task #556).
 */
import { utf8ToBytes } from '@noble/hashes/utils.js';
import {
  sealToMailbox,
  openMailboxEnvelope,
  type MailboxEnvelopePackage,
  type MailboxPublicKeys,
  type MailboxSecretKeys,
} from './mailbox-envelope.js';

/** The INNER package as it travels inside the OUTER shell: the co-verified envelope MINUS its stable
 * `mailbox_fp` (K0-1 blinding). The device re-inserts its own fp at open via openOnionInner. */
export type StrippedInner = Omit<MailboxEnvelopePackage, 'mailbox_fp'>;

/** The OUTER shell's plaintext (sealed to the satellite): a routing datum + the fp-stripped INNER. */
export interface OnionOuterPayload {
  /**
   * Routing instruction the satellite reads AFTER peeling. K1 (§5) fills this with the blinded rotating
   * route_id; at K0 it is an opaque passthrough string.
   */
  route: string;
  /** The INNER package — still sealed to the recipient DEVICE keys, with `mailbox_fp` STRIPPED (K0-1). */
  inner: StrippedInner;
}

/**
 * SEAL the OUTER shell: strip the inner's stable `mailbox_fp` (K0-1 blinding), wrap it + a routing datum,
 * and seal to the SATELLITE's keys. The outer's own mailbox_fp is DERIVED from the satellite pubkeys
 * (never supplied — footgun-B).
 */
export async function sealOnion(
  inner: MailboxEnvelopePackage,
  satellite: MailboxPublicKeys,
  route: string,
): Promise<MailboxEnvelopePackage> {
  const { mailbox_fp, ...innerNoFp } = inner; // strip the ONLY stable field before it hits the wire
  void mailbox_fp; // intentionally dropped (K0-1); the device re-supplies its own fp at open
  const payload: OnionOuterPayload = { route, inner: innerNoFp };
  return sealToMailbox(utf8ToBytes(JSON.stringify(payload)), satellite); // no fp arg → derived (footgun-B)
}

/**
 * PEEL the OUTER shell with the SATELLITE's secrets → the routing datum + the fp-stripped INNER.
 * Returns null on ANY rejection (wrong satellite / tamper / malformed) and NEVER throws on hostile input.
 * Defensively deletes any `mailbox_fp` a malformed wire might carry, so a peeled inner is always stripped
 * (the K0-1 invariant holds on output regardless of the wire).
 */
export async function peelOnion(
  outer: MailboxEnvelopePackage,
  satelliteSecrets: MailboxSecretKeys,
  satelliteMailboxFpHex: string,
): Promise<OnionOuterPayload | null> {
  const pt = await openMailboxEnvelope(outer, satelliteSecrets, satelliteMailboxFpHex);
  if (pt === null) return null; // wrong recipient / tamper / malformed envelope

  let obj: unknown;
  try {
    obj = JSON.parse(new TextDecoder().decode(pt));
  } catch {
    return null; // outer opened but plaintext isn't our JSON shape
  }
  if (
    obj === null ||
    typeof obj !== 'object' ||
    typeof (obj as OnionOuterPayload).route !== 'string' ||
    typeof (obj as { inner?: unknown }).inner !== 'object' ||
    (obj as { inner?: unknown }).inner === null
  ) {
    return null;
  }
  const inner = (obj as { inner: Record<string, unknown> }).inner;
  delete inner.mailbox_fp; // enforce the K0-1 blinding invariant on the peel output unconditionally
  return { route: (obj as OnionOuterPayload).route, inner: inner as unknown as StrippedInner };
}

/**
 * DEVICE-side: re-insert the device's OWN mailbox_fp into a peeled (stripped) inner and open it. The
 * satellite never saw the fp; the device knows its own. Byte-identical to opening an unstripped package
 * because openMailboxEnvelope derives the KDF info + AAD from the (now-reinserted) fp, which must equal
 * `deviceMailboxFpHex`. Returns plaintext, or null on any rejection.
 */
export async function openOnionInner(
  inner: StrippedInner,
  deviceSecrets: MailboxSecretKeys,
  deviceMailboxFpHex: string,
): Promise<Uint8Array | null> {
  const reconstructed = { ...inner, mailbox_fp: deviceMailboxFpHex } as MailboxEnvelopePackage;
  return openMailboxEnvelope(reconstructed, deviceSecrets, deviceMailboxFpHex);
}
