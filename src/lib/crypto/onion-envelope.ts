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
 * The satellite peels the OUTER with its OWN keypair (peelOnion) → learns only the routing datum + the
 * still-sealed INNER. It CANNOT read the content: INNER is sealed to the DEVICE, not the satellite. This
 * is the two-keypair separation the keystone rests on (spec §2/§3): satellite keypair ≠ device keypair.
 * The outer shell is reject-classical by construction (it IS a mailbox envelope) → nothing classical over
 * the wire (spec §9 / consumer #3).
 *
 * K0 SCOPE = this client-side nest/peel primitive. The satellite keypair generation/hosting + the
 * server-side peel/route wiring are separate (a server keypair module + the external satellite service).
 * The blinded, rotating `route` id is K1 (§5 ratchet); here `route` is an opaque passthrough string.
 *
 * Footgun-B (KB#91308): sealOnion NEVER accepts a supplied outer mailbox_fp — it is derived from the
 * satellite pubkeys inside sealToMailbox (no fp arg), so an attacker can't aim the outer AAD at a mailbox
 * whose keys don't match.
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

/** The OUTER shell's plaintext (sealed to the satellite): a routing datum + the still-device-sealed INNER. */
export interface OnionOuterPayload {
  /**
   * Routing instruction the satellite reads AFTER peeling. K1 (§5) fills this with the blinded rotating
   * route_id; at K0 it is an opaque passthrough string. Visible only to the peeling satellite, never on
   * the outer wire (the wire routing datum, if any, is separate — spec §5 `wire = {route, pkg}`).
   */
  route: string;
  /** The INNER package — still sealed to the recipient DEVICE keys. The satellite routes it without reading it. */
  inner: MailboxEnvelopePackage;
}

/**
 * SEAL the OUTER shell: wrap an already-device-sealed INNER package + a routing datum, sealed to the
 * SATELLITE's keys. Returns a MailboxEnvelopePackage (the outer). Its mailbox_fp is DERIVED from the
 * satellite pubkeys (never supplied — footgun-B).
 */
export async function sealOnion(
  inner: MailboxEnvelopePackage,
  satellite: MailboxPublicKeys,
  route: string,
): Promise<MailboxEnvelopePackage> {
  const payload: OnionOuterPayload = { route, inner };
  return sealToMailbox(utf8ToBytes(JSON.stringify(payload)), satellite); // no fp arg → derived (footgun-B)
}

/**
 * PEEL the OUTER shell with the SATELLITE's secrets → the routing datum + the still-sealed INNER.
 * Returns null on ANY rejection (wrong satellite / tamper / malformed) and NEVER throws on hostile input
 * — the outer plaintext is attacker-influenced, and this inherits openMailboxEnvelope's null-on-reject
 * contract (relevant to satellite-side consumers that don't wrap the call).
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
    typeof (obj as OnionOuterPayload).inner !== 'object' ||
    (obj as OnionOuterPayload).inner === null
  ) {
    return null;
  }
  return { route: (obj as OnionOuterPayload).route, inner: (obj as OnionOuterPayload).inner };
}
