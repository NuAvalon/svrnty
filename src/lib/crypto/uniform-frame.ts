// src/lib/crypto/uniform-frame.ts
/**
 * Uniform framing substrate — the #558 keystone K2 (§6/§8, Flint Finding-#1).
 *
 * WHAT IT IS: a fixed-size CELL codec that sits UNDER the K0 inner seal. Its one job is to make three
 * kinds of payload — a **consent-delta** (K2, §6), a **message**, and a **distress** cry (K3, §8) —
 * BYTE-INDISTINGUISHABLE to a hosted satellite that PEELS the K0 outer shell, along the three axes Flint
 * flagged (Finding-#1, KB#91381):
 *
 *   ┌ type       — the payload kind must not be readable off the wire.
 *   ┤ SIZE       — the payload length must not fingerprint the kind (★ the green-flatter: a "type-tag-
 *   │              stripped" frame still leaks the kind by LENGTH unless every cell is padded to one size).
 *   └ fwd-pointer— any fan-out pointer must be a blinded rotating id (K1 route_id), never a stable cleartext.
 *
 * This is what lets a consent-delta be "a signal the relay routes but cannot READ" (spec §7): without a
 * uniform frame, a peeling satellite classifies "this is a consent change" by its type tag or its length,
 * and the §C-firewall extension (§9) would be a false claim.
 *
 * WHERE IT SITS (grounded on onion-envelope.ts K0 + mailbox-envelope.ts):
 *
 *     payload (consent-delta | message | distress bytes)  +  type
 *        │  frameUniform → a constant FRAME_BYTES cell: [ver|type|len|payload|RANDOM PAD]
 *        ▼                 (the type byte lives INSIDE the cell → device-sealed → relay never sees it)
 *     cell  (constant length; type hidden)
 *        │  sealToMailbox(cell, DEVICE keys)      ── K0 INNER ──▶  inner.ct length is CONSTANT across types
 *        ▼                                          (AES-GCM ct len = plaintext len + 16; plaintext len is fixed)
 *     INNER  (MailboxEnvelopePackage — every field fixed-length; only `ct` varied, now pinned constant)
 *        │  sealOnion(INNER, SATELLITE keys, route_id)   ── K0 OUTER + K1 route_id ──▶
 *        ▼
 *     OUTER  — a peeling satellite sees: a constant-length ct + a blinded rotating route_id. Nothing else.
 *
 * WHY THE PAD IS ON THE INNER PLAINTEXT (the load-bearing detail): a satellite that peels the OUTER reads
 * `inner.ct`, whose AEAD length equals the inner plaintext length. Padding only the OUTER would NOT hide the
 * kind from a peeling relay — the inner.ct still leaks it. So the cell (the inner plaintext) is what must be
 * constant-size. Every other envelope field (epk 32B, kem_ct 1568B, nonce 12B) is already fixed-length and
 * identical across kinds; only `ct` moved, and the constant cell pins it.
 *
 * ★ CLAIM BOUNDARY (do-no-harm, stated so it is not silently overclaimed): a fixed cell makes a SINGLE cell
 * indistinguishable by type / size / fwd-pointer. A payload larger than FRAME_MAX_PAYLOAD needs MULTIPLE
 * cells, and the CELL COUNT is a coarse VOLUME signal that reveals "this is a long message" — but it does NOT
 * separate the sensitive single-cell kinds from each other: a consent-delta, a distress cry, and a SHORT
 * message are all one cell and mutually indistinguishable. The volume signal only exposes long messages,
 * which are not the protected class. Multi-cell chunking of long messages is the message path's concern
 * (deferred, like K0 deferred satellite-serve / K1 deferred Family-B wiring); this module frames one cell.
 *
 * SCOPE (K2-substrate = this codec + its adversarial Finding-#1 gate). Its first consumer — the signed
 * consent-delta (§6) — is consent-delta.ts. Distress (K3, §8) reuses this SAME codec (a distress cry must
 * hide inside the same uniform traffic, never on a self-classifying dedicated channel — spec §8). The consent
 * EMIT-PATH (C's toggle → per-contact fan-out → satellite deposit) + the §C-firewall wiring are a separate
 * reviewable unit (Flint §7 gates it); NOT built here.
 *
 * NO new crypto core: this is pure byte-framing + WebCrypto randomness for the pad. The confidentiality is
 * entirely the K0/mailbox-envelope seal that wraps the cell.
 */

/** Fixed cell size in bytes (the constant every framed payload is padded to).
 *
 *  ★ TUNABLE KNOB, NOT ARCHITECTURE: the ARCHITECTURE is "one fixed cell size for all kinds" (that is the
 *  invariant the Finding-#1 gate proves). The VALUE is a bandwidth-vs-coverage tradeoff for measurement / the
 *  threat model to tune (like route-ratchet's ROUTE_WINDOW_SECONDS): larger ⇒ more short messages fit in one
 *  cell (so control-plane packets hide among ordinary single-cell messages) at the cost of padding overhead on
 *  tiny consent/distress packets. 2 KiB comfortably holds a consent-delta (~90 B) and a typical short chat
 *  message in ONE cell, so those share a length distribution; long messages spill to multiple cells (boundary
 *  above). Change ⇒ bump FRAME_VERSION (the wire length is version-bound). */
export const FRAME_BYTES = 2048;

/** Cell wire version — pinned into byte 0 so a device can reject a cell it cannot parse (and so FRAME_BYTES
 *  can change in a later version without silently mis-parsing an old cell). */
export const FRAME_VERSION = 1;

/** Header layout (fixed 6 bytes): [0]=version, [1]=typeCode, [2..5]=payloadLen (uint32 BE). */
const HEADER_BYTES = 6;

/** Largest single-cell payload. A payload beyond this MUST be split by the caller (deferred message path). */
export const FRAME_MAX_PAYLOAD = FRAME_BYTES - HEADER_BYTES;

/** The kinds that share the uniform channel. The kind is carried ONLY inside the device-sealed cell — it is
 *  never a wire-legible tag (type-opacity). Distinct byte codes; 0 is reserved-invalid so an all-zero buffer
 *  never unframes to a valid kind. `cover` is the K3/§8b uniform-baseline cover traffic (defined here so the
 *  channel's type space is complete; its emitter is K3). */
export type FrameType = 'consent-delta' | 'message' | 'distress' | 'cover';

const TYPE_TO_CODE: Record<FrameType, number> = {
  'consent-delta': 1,
  message: 2,
  distress: 3,
  cover: 4,
};
const CODE_TO_TYPE: Record<number, FrameType> = {
  1: 'consent-delta',
  2: 'message',
  3: 'distress',
  4: 'cover',
};

/**
 * FRAME a payload into a constant FRAME_BYTES cell whose kind and length are recoverable ONLY after the inner
 * device-seal is opened. The pad region is filled with fresh CSPRNG bytes (defense-in-depth: if a plaintext
 * cell ever leaked, the pad carries no structure; on the wire it is sealed regardless). The kind byte and the
 * length live inside the cell → constant total length across ALL kinds → no size or type fingerprint.
 *
 * Throws (never silently truncates) if the payload does not fit one cell — the caller must split, and a silent
 * truncation would be a correctness/security bug (a clipped consent-delta could verify wrong).
 */
export function frameUniform(payload: Uint8Array, type: FrameType): Uint8Array {
  if (!(payload instanceof Uint8Array)) throw new Error('uniform-frame: payload must be a Uint8Array');
  if (payload.length > FRAME_MAX_PAYLOAD) {
    throw new Error(`uniform-frame: payload ${payload.length} exceeds one cell (${FRAME_MAX_PAYLOAD}) — caller must split`);
  }
  const code = TYPE_TO_CODE[type];
  if (code === undefined) throw new Error(`uniform-frame: unknown frame type ${String(type)}`);

  // Fill the WHOLE cell with random first; then overwrite the header + payload. What remains after the
  // payload is random pad — no separate pad step, and the pad is genuinely CSPRNG.
  const cell = crypto.getRandomValues(new Uint8Array(FRAME_BYTES));
  const view = new DataView(cell.buffer, cell.byteOffset, cell.byteLength);
  cell[0] = FRAME_VERSION;
  cell[1] = code;
  view.setUint32(2, payload.length, false); // big-endian
  cell.set(payload, HEADER_BYTES);
  return cell;
}

/**
 * DEVICE-side: recover { type, payload } from a peeled+opened cell. Returns null on ANY malformation
 * (wrong length, unknown version/type, or an internal length that overruns the cell) and NEVER throws on
 * hostile input — the same null-not-throw contract as openMailboxEnvelope, because a hostile relay controls
 * the ciphertext that decrypts to this buffer.
 */
export function unframeUniform(cell: Uint8Array): { type: FrameType; payload: Uint8Array } | null {
  if (!(cell instanceof Uint8Array) || cell.length !== FRAME_BYTES) return null; // constant length IS the contract
  if (cell[0] !== FRAME_VERSION) return null;
  const type = CODE_TO_TYPE[cell[1]];
  if (type === undefined) return null;
  const view = new DataView(cell.buffer, cell.byteOffset, cell.byteLength);
  const len = view.getUint32(2, false);
  if (len > FRAME_MAX_PAYLOAD) return null; // an internal length that would overrun the cell — reject
  return { type, payload: cell.slice(HEADER_BYTES, HEADER_BYTES + len) };
}
