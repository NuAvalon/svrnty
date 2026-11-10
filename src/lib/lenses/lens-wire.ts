// src/lib/lenses/lens-wire.ts
/**
 * Lenses v1.3 — the sealed per-recipient LENS PAYLOAD wire codec (the lenses v1.3 contract, R4/R8).
 *
 * WHAT A LENS PAYLOAD IS: a NEW SCHEMA, not a card field and not a contact.update. It carries the
 * methods of ONE lens to ONE recipient — privately, inside the existing hybrid mailbox seal. The
 * LENS NAME and the recipient→lens record NEVER appear here (R1): the payload carries methods,
 * a monotonic seq, and the sender fingerprint — nothing else.
 *
 * TWO KINDS, one frame type:
 *   • 'hello'   — the "can take it" signal (R7). A lens-capable client announces itself to a
 *                 contact with this sealed frame. It is NOT a card field and is invisible to the
 *                 relay (it rides the same sealed mailbox blob as every other deposit). A sender
 *                 must NOT send 'methods' to a recipient who has not said hello.
 *   • 'methods' — the lens's methods, privately. Later updates re-send the recipient's CURRENT
 *                 lens set (idempotent; a revoked method simply stops updating — R6 honesty:
 *                 nothing takes back what was already delivered).
 *
 * PLAINTEXT (the payload that frameUniform pads to the uniform FRAME_BYTES cell — R8):
 *
 *   header(2) || kind(1) || fp_sender(32 raw) || seq u64be(8) || bodyLen u32be(4) || body || tag(32)
 *
 * Every lens cell is the SAME 2048 bytes whatever the lens holds: neither the lens count, the
 * recipient's assignment, nor the method count is legible on the wire beyond the payload's
 * existence (the methods themselves can tell a recipient roughly which face they got — expected).
 *
 * MAC, NOT A SIGNATURE (R4 — the payload is not transferable proof):
 *   K_mac = HKDF-SHA256(S_pair, salt='svrnty-lens-auth-v1',
 *                       info='lens-mac' || LP(fp_sender) || LP(fp_receiver), 32)
 *   tag   = HMAC-SHA256(K_mac, header || kind || fp_sender || fp_receiver || seq || bodyLen || body)
 * Same construction as psi-epoch-note.ts: every preimage field is fixed-width so no two field
 * splits collide, the sender comes FIRST in both the info and the preimage — a reflected payload,
 * or one replayed in the other direction, fails. A recipient can repeat what they were given but
 * cannot present the payload to a third party as proof the sender authored it.
 *
 * CLAIM BOUNDARY (stated, R4): the SEAL is hybrid (X25519 + ML-KEM-1024, living-book-sleeve), but
 * the AUTHENTICITY of this MAC is CLASSICAL until a hybrid pair secret exists — S_pair today is the
 * X25519(ed25519→montgomery) identity-leg secret via deriveSharedSecret. Never reuse another
 * protocol's key: own salt, own info label.
 *
 * S_pair is an INPUT (the caller derives it from the identity keys); it is never stored here.
 * A payload from ourselves (fp_sender == fp_receiver) is refused when building and when opening.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { lpStr, u64be } from '../crypto/lp-tlv';
import { ctEqual } from '../crypto/ct-equal';
import { frameUniform, unframeUniform, FRAME_MAX_PAYLOAD } from '../crypto/uniform-frame';
import { normalizeFingerprintHex } from '../identity/fingerprint';

/** Wire type 0x4C ('L') and version 1 — carried ONLY inside the device-sealed uniform cell. */
export const LENS_HEADER = Uint8Array.of(0x4c, 0x01);
export const LENS_TAG_LEN = 32;

export const LENS_KIND_HELLO = 0x01;
export const LENS_KIND_METHODS = 0x02;
export type LensKind = typeof LENS_KIND_HELLO | typeof LENS_KIND_METHODS;

const MAC_SALT = 'svrnty-lens-auth-v1';
const MAC_INFO = 'lens-mac';
const CANONICAL_FP = /^[0-9a-f]{64}$/;
const PAIR_SECRET_LEN = 32;

/** Fixed-layout bounds: header(2) + kind(1) + fp(32) + seq(8) + bodyLen(4). */
const FIXED_BYTES = 2 + 1 + 32 + 8 + 4;

/** Wire bounds on the methods body (defence at the codec edge; the send composer filters before this). */
export const LENS_MAX_METHODS = 32;
export const LENS_METHOD_KIND_MAX_LEN = 32;
export const LENS_METHOD_VALUE_MAX_LEN = 512;
export const LENS_METHOD_LABEL_MAX_LEN = 64;
export const LENS_HELLO_BODY = utf8ToBytes('{"v":1}');

/** The most body bytes one payload can carry and still frame into the single 2048B cell:
 *  FRAME_MAX_PAYLOAD minus the fixed layout (header+kind+fp+seq+bodyLen) and the MAC tag. */
export const LENS_MAX_BODY = FRAME_MAX_PAYLOAD - FIXED_BYTES - LENS_TAG_LEN;

/**
 * The SLOT identity of a wire method: kind + a NUL separator + label (empty when absent). NUL can
 * never appear in a wire kind or label (both are bounded printable fields), so two different
 * (kind,label) pairs can never collide on one key. Written as a source escape — a literal NUL byte
 * in the file would make git treat the whole file as binary and invisible to review.
 */
export const lensMethodKey = (m: Pick<LensMethodWire, 'kind' | 'label'>): string =>
  `${m.kind}\x00${m.label ?? ''}`;

export interface LensMethodWire {
  kind: string;
  value: string;
  label?: string;
}

export class LensWireError extends Error {
  constructor(readonly code: 'bad-fingerprint' | 'self-send' | 'bad-pairwise-secret' | 'bad-kind' | 'bad-seq' | 'bad-body', detail: string) {
    super(`lens-wire: ${code}: ${detail}`);
    this.name = 'LensWireError';
  }
}

export interface LensPairContext {
  /** The 32-byte pairwise secret between sender and receiver (the caller derives it; it is not kept here). */
  sPair: Uint8Array;
  /** Canonical lowercase 64-hex fingerprints. */
  fpSender: string;
  fpReceiver: string;
}

function checkContext(ctx: LensPairContext): void {
  for (const fp of [ctx.fpSender, ctx.fpReceiver]) {
    if (typeof fp !== 'string' || !CANONICAL_FP.test(normalizeFingerprintHex(fp))) {
      throw new LensWireError('bad-fingerprint', 'not canonical (64-hex)');
    }
  }
  if (!(ctx.sPair instanceof Uint8Array) || ctx.sPair.length !== PAIR_SECRET_LEN) {
    throw new LensWireError('bad-pairwise-secret', `must be exactly ${PAIR_SECRET_LEN} bytes`);
  }
}

function checkSeq(seq: number): void {
  if (!Number.isSafeInteger(seq) || seq < 0) throw new LensWireError('bad-seq', 'must be a non-negative safe integer');
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/** K_mac for one direction (sender first). Derived per use; the caller must not keep it. */
export function deriveLensMacKey(ctx: LensPairContext): Uint8Array {
  checkContext(ctx);
  const info = concatBytes(utf8ToBytes(MAC_INFO), lpStr(normalizeFingerprintHex(ctx.fpSender)), lpStr(normalizeFingerprintHex(ctx.fpReceiver)));
  return hkdf(sha256, ctx.sPair, utf8ToBytes(MAC_SALT), info, 32);
}

function macPreimage(ctx: LensPairContext, kind: number, seq: number, bodyLen: number, body: Uint8Array): Uint8Array {
  return concatBytes(
    LENS_HEADER,
    Uint8Array.of(kind),
    hexToBytes(normalizeFingerprintHex(ctx.fpSender)),
    hexToBytes(normalizeFingerprintHex(ctx.fpReceiver)),
    u64be(seq),
    u32be(bodyLen),
    body,
  );
}

function tagOf(ctx: LensPairContext, kind: number, seq: number, body: Uint8Array): Uint8Array {
  return hmac(sha256, deriveLensMacKey(ctx), macPreimage(ctx, kind, seq, body.length, body));
}

/** Encode the methods body (deterministic field order so a re-encode of the same list is byte-equal). */
export function encodeLensMethodsBody(methods: LensMethodWire[]): Uint8Array {
  if (!Array.isArray(methods) || methods.length > LENS_MAX_METHODS) {
    throw new LensWireError('bad-body', `methods must be a list of at most ${LENS_MAX_METHODS}`);
  }
  for (const m of methods) {
    if (typeof m?.kind !== 'string' || m.kind.length === 0 || m.kind.length > LENS_METHOD_KIND_MAX_LEN) {
      throw new LensWireError('bad-body', 'method kind missing or oversized');
    }
    if (typeof m?.value !== 'string' || m.value.length === 0 || m.value.length > LENS_METHOD_VALUE_MAX_LEN) {
      throw new LensWireError('bad-body', 'method value missing or oversized');
    }
    if (m.label !== undefined && (typeof m.label !== 'string' || m.label.length > LENS_METHOD_LABEL_MAX_LEN)) {
      throw new LensWireError('bad-body', 'method label oversized');
    }
  }
  return utf8ToBytes(JSON.stringify(methods.map((m) => (m.label === undefined ? { kind: m.kind, value: m.value } : { kind: m.kind, value: m.value, label: m.label }))));
}

/** Parse + bound a methods body. Throws LensWireError('bad-body') on any malformation — the caller treats that as a drop. */
export function decodeLensMethodsBody(body: Uint8Array): LensMethodWire[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new LensWireError('bad-body', 'body is not JSON');
  }
  if (!Array.isArray(parsed) || parsed.length > LENS_MAX_METHODS) throw new LensWireError('bad-body', 'methods list missing or oversized');
  const out: LensMethodWire[] = [];
  for (const m of parsed) {
    if (typeof m?.kind !== 'string' || m.kind.length === 0 || m.kind.length > LENS_METHOD_KIND_MAX_LEN) throw new LensWireError('bad-body', 'method kind');
    if (typeof m?.value !== 'string' || m.value.length === 0 || m.value.length > LENS_METHOD_VALUE_MAX_LEN) throw new LensWireError('bad-body', 'method value');
    const label = m.label === undefined ? undefined : typeof m.label === 'string' && m.label.length <= LENS_METHOD_LABEL_MAX_LEN ? m.label : undefined;
    if (m.label !== undefined && label === undefined) throw new LensWireError('bad-body', 'method label');
    out.push(label === undefined ? { kind: m.kind, value: m.value } : { kind: m.kind, value: m.value, label });
  }
  return out;
}

export interface BuildLensArgs extends LensPairContext {
  kind: LensKind;
  seq: number;
  body: Uint8Array;
}

/**
 * The framed PLAINTEXT for one recipient (header || kind || fp || seq || len || body || tag).
 * Throws on a body that cannot fit one cell — a silent truncation could flip a MAC verification.
 */
export function buildLensPayload(args: BuildLensArgs): Uint8Array {
  checkContext(args);
  if (args.fpSender === args.fpReceiver) throw new LensWireError('self-send', 'sender and receiver are the same fingerprint');
  if (args.kind !== LENS_KIND_HELLO && args.kind !== LENS_KIND_METHODS) throw new LensWireError('bad-kind', 'unknown lens kind');
  checkSeq(args.seq);
  if (!(args.body instanceof Uint8Array)) throw new LensWireError('bad-body', 'body must be bytes');
  const tag = tagOf(args, args.kind, args.seq, args.body);
  return concatBytes(
    LENS_HEADER,
    Uint8Array.of(args.kind),
    hexToBytes(normalizeFingerprintHex(args.fpSender)),
    u64be(args.seq),
    u32be(args.body.length),
    args.body,
    tag,
  );
}

/** The uniform FRAME_BYTES cell carrying one lens payload (R8: one fixed shape whatever the lens holds). */
export function buildLensCell(args: BuildLensArgs): Uint8Array {
  return frameUniform(buildLensPayload(args), 'lens');
}

/** The unverified structural parse — the consume seam's discriminator. Null on any non-lens cell. */
export interface ParsedLensPayload {
  kind: LensKind;
  fpSender: string;
  seq: number;
  body: Uint8Array;
  tag: Uint8Array;
}

export function parseLensPayload(payload: Uint8Array): ParsedLensPayload | null {
  if (!(payload instanceof Uint8Array) || payload.length < FIXED_BYTES + LENS_TAG_LEN) return null;
  if (payload[0] !== LENS_HEADER[0] || payload[1] !== LENS_HEADER[1]) return null;
  const kind = payload[2];
  if (kind !== LENS_KIND_HELLO && kind !== LENS_KIND_METHODS) return null;
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const seqBig = view.getBigUint64(3 + 32, false);
  if (seqBig > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const bodyLen = view.getUint32(3 + 32 + 8, false);
  if (payload.length !== FIXED_BYTES + bodyLen + LENS_TAG_LEN) return null;
  return {
    kind: kind as LensKind,
    fpSender: Array.from(payload.slice(3, 35), (b) => b.toString(16).padStart(2, '0')).join(''),
    seq: Number(seqBig),
    body: payload.slice(FIXED_BYTES, FIXED_BYTES + bodyLen),
    tag: payload.slice(FIXED_BYTES + bodyLen),
  };
}

/** Unframe a uniform cell into a parsed lens payload (null when the cell is not a lens frame or is malformed). */
export function unframeLensCell(cell: Uint8Array): ParsedLensPayload | null {
  const framed = unframeUniform(cell);
  if (!framed || framed.type !== 'lens') return null;
  return parseLensPayload(framed.payload);
}

export type LensOpenRejection = 'malformed' | 'self' | 'bad-mac';

export type OpenedLensPayload =
  | { ok: true; kind: LensKind; fpSender: string; seq: number; body: Uint8Array }
  | { ok: false; reason: LensOpenRejection };

/**
 * Parse + authenticate a received plaintext. ctx.fpReceiver MUST be the owner opening the cell and
 * ctx.fpSender the claimed sender (from the payload — verified by the MAC, not trusted before). The
 * reason is for a local counter only; nothing derived from it may leave the device.
 */
export function openLensPayload(payload: Uint8Array, ctx: LensPairContext): OpenedLensPayload {
  checkContext(ctx);
  const parsed = parseLensPayload(payload);
  if (!parsed) return { ok: false, reason: 'malformed' };
  if (parsed.fpSender !== normalizeFingerprintHex(ctx.fpSender)) return { ok: false, reason: 'malformed' }; // claimed ≠ ctx: the MAC context is wrong anyway — drop as malformed
  if (normalizeFingerprintHex(ctx.fpSender) === normalizeFingerprintHex(ctx.fpReceiver)) return { ok: false, reason: 'self' };
  const want = tagOf(ctx, parsed.kind, parsed.seq, parsed.body);
  if (!ctEqual(want, parsed.tag)) return { ok: false, reason: 'bad-mac' };
  return { ok: true, kind: parsed.kind, fpSender: parsed.fpSender, seq: parsed.seq, body: parsed.body };
}
