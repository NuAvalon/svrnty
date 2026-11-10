// src/lib/trust/key-rotate-wire.ts
/**
 * `key.rotate` wire object: the BYTES of a rotation successor (task #809, foundation step 1). DARK: nothing in the app imports this
 * module; it is pure bytes-in, bytes-out plus one typed gate (below). No I/O, no clock, no secrets.
 *
 * Layout (all integers big-endian; every field but the armored key has a FIXED width, so there is nothing to guess):
 *   header   4   'K' 'R' version(0x01) kind(0x01 = rotation)
 *   durable_id            32   the contact's genesis fingerprint, raw
 *   prior_epoch           8    u64
 *   successor_epoch       8    u64
 *   new_fingerprint       32   raw
 *   next_authority_commitment 32  raw (the pin for the epoch AFTER this successor)
 *   new_public_key        LP   armored OpenPGP key, UTF-8, at most 16 KiB
 *   new_pq_kem_public_key 1568 ML-KEM-1024 encapsulation key
 *   new_pq_sig_public_key 2592 ML-DSA-87 public key
 *   authority reveal      32 + 2592   ed25519 and ML-DSA-87 public keys (their hash must equal the receiver's pinned commitment)
 *   sig_by_authority      64 + 4627   ed25519 and ML-DSA-87 signatures
 * `prior_authority_commitment` is signed but NOT carried: the receiver supplies it from the pin it already holds (verifyRotationSuccessor),
 * so a sender cannot choose it.
 *
 * Why binary and not JSON or hex: one strict parser style for every binary object (lp-reader.ts), fixed widths, and about half the bytes.
 *
 * THE GATE: `parseKeyRotate` returns an `UnverifiedKeyRotate` that exposes NOTHING. Its only method is `verify(known)`, which runs the
 * existing verifier (verifyRotationSuccessor) and returns the adopted identity only if every check passes. No parsed field reaches a
 * caller before that. A refusal carries a stable reason code and never an attacker byte (the verifier's own detail text is dropped).
 */
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { LpReader, LpParseError } from '../crypto/lp-reader';
import { lpBin, u64be } from '../crypto/lp-tlv';
import { uint8ToBase64, base64ToUint8 } from '../crypto/pq';
import {
  verifyRotationSuccessor,
  ContactUpdateRejected,
  type RotationSuccessorInput,
  type KnownContactIdentity,
  type AdoptedRotationIdentity,
} from './contact-update';

export const KEY_ROTATE_MAGIC = Uint8Array.of(0x4b, 0x52); // 'KR'
export const KEY_ROTATE_VERSION = 0x01;
export const KEY_ROTATE_KIND_ROTATION = 0x01;

export const KEY_ROTATE_ARMORED_MAX = 16 * 1024;
const FP_LEN = 32;
const KEM_PUB_LEN = 1568;
const DSA_PUB_LEN = 2592;
const ED_PUB_LEN = 32;
const ED_SIG_LEN = 64;
const DSA_SIG_LEN = 4627;
const HEX64 = /^[0-9a-f]{64}$/;

/** A refusal of an encode or a verify, with a stable reason and no input bytes. */
export class KeyRotateRefused extends Error {
  constructor(public readonly reason: string) {
    super(`key.rotate refused (${reason})`);
    this.name = 'KeyRotateRefused';
  }
}

function hex32(h: unknown): Uint8Array {
  if (typeof h !== 'string' || !HEX64.test(h)) throw new KeyRotateRefused('bad-hex32');
  return hexToBytes(h);
}

function b64Exact(s: unknown, len: number): Uint8Array {
  if (typeof s !== 'string') throw new KeyRotateRefused('bad-base64');
  let b: Uint8Array;
  try {
    b = base64ToUint8(s);
  } catch {
    throw new KeyRotateRefused('bad-base64');
  }
  if (b.length !== len || uint8ToBase64(b) !== s) throw new KeyRotateRefused('bad-length'); // exact width and canonical text
  return b;
}

function hexExact(s: unknown, len: number): Uint8Array {
  if (typeof s !== 'string' || !/^[0-9a-f]*$/.test(s) || s.length !== len * 2) throw new KeyRotateRefused('bad-hex');
  return hexToBytes(s);
}

function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Encode a rotation successor. Throws KeyRotateRefused on any field of the wrong shape or width. */
export function encodeKeyRotate(s: RotationSuccessorInput): Uint8Array {
  const auth = s?.auth;
  if (!auth || auth.kind !== 'rotation') throw new KeyRotateRefused('not-a-rotation');
  const a = auth as { auth_pubkeys: { sign: string; pq_sig: string }; sig_by_authority: string };
  if (!Number.isSafeInteger(s.prior_epoch) || s.prior_epoch < 0) throw new KeyRotateRefused('bad-epoch');
  if (!Number.isSafeInteger(s.successor_epoch) || s.successor_epoch < 0) throw new KeyRotateRefused('bad-epoch');
  if (typeof s.new_public_key !== 'string' || !isArmoredPublicKeyShape(s.new_public_key)) throw new KeyRotateRefused('bad-key');
  const armored = new TextEncoder().encode(s.new_public_key);
  if (armored.length > KEY_ROTATE_ARMORED_MAX) throw new KeyRotateRefused('key-too-large');
  const sig = hexExact(a.sig_by_authority, ED_SIG_LEN + DSA_SIG_LEN);
  return concat([
    KEY_ROTATE_MAGIC,
    Uint8Array.of(KEY_ROTATE_VERSION, KEY_ROTATE_KIND_ROTATION),
    hex32(s.durable_id),
    u64be(s.prior_epoch),
    u64be(s.successor_epoch),
    hex32(s.new_fingerprint),
    hex32(s.next_authority_commitment),
    lpBin(armored),
    b64Exact(s.new_pq_kem_public_key, KEM_PUB_LEN),
    b64Exact(s.new_pq_sig_public_key, DSA_PUB_LEN),
    hexExact(a.auth_pubkeys.sign, ED_PUB_LEN),
    hexExact(a.auth_pubkeys.pq_sig, DSA_PUB_LEN),
    sig,
  ]);
}

// The parsed fields live in a module-private map keyed by the opaque object: there is no property to read.
const FIELDS = new WeakMap<object, RotationSuccessorInput>();

export interface VerifiedKeyRotate {
  /** The identity to adopt, as the existing verifier returns it. */
  readonly adopted: AdoptedRotationIdentity;
  /** The verified successor input (available only after verification). */
  readonly successor: Readonly<RotationSuccessorInput>;
}

export class UnverifiedKeyRotate {
  // Not constructible outside this module.
  private constructor() {}

  /** @internal used by parseKeyRotate only */
  static __make(input: RotationSuccessorInput): UnverifiedKeyRotate {
    const o = new UnverifiedKeyRotate();
    FIELDS.set(o, input);
    return o;
  }

  /**
   * UNVERIFIED, for routing only: the successor epoch this object CLAIMS. It lets a receiver tell a stale object (acked) from one that is
   * ahead (kept for retry) without running the verifier on a claim that cannot chain yet. Never trust it: nothing but verify() returns a
   * field a caller may act on, and a wrong claim only chooses a branch that changes no state.
   */
  claimedSuccessorEpoch(): number {
    const input = FIELDS.get(this);
    if (!input) throw new KeyRotateRefused('no-fields');
    return input.successor_epoch;
  }

  /** Run the existing rotation verifier against the contact we hold. Nothing is returned unless it all passes. */
  async verify(known: KnownContactIdentity): Promise<VerifiedKeyRotate> {
    const input = FIELDS.get(this);
    if (!input) throw new KeyRotateRefused('no-fields');
    try {
      const adopted = await verifyRotationSuccessor(input, known);
      const auth = input.auth as { kind: 'rotation'; auth_pubkeys: { sign: string; pq_sig: string }; sig_by_authority: string };
      const successor = Object.freeze({
        ...input,
        auth: Object.freeze({ ...auth, auth_pubkeys: Object.freeze({ ...auth.auth_pubkeys }) }),
      }) as Readonly<RotationSuccessorInput>;
      return Object.freeze({ adopted: Object.freeze({ ...adopted }), successor });
    } catch (e) {
      if (e instanceof ContactUpdateRejected) throw new KeyRotateRefused(e.reason); // the verifier's detail text can hold input: dropped
      throw new KeyRotateRefused('verify-failed');
    }
  }
}

/** Parse a key.rotate object. Strict: exact header, exact widths, no trailing byte. Throws LpParseError (a reason code only). */
export function parseKeyRotate(bytes: Uint8Array): UnverifiedKeyRotate {
  const r = new LpReader(bytes);
  const magic = r.readFixed(2);
  if (magic[0] !== KEY_ROTATE_MAGIC[0] || magic[1] !== KEY_ROTATE_MAGIC[1]) throw new LpParseError('bad-header');
  if (r.readU8() !== KEY_ROTATE_VERSION) throw new LpParseError('bad-header');
  if (r.readU8() !== KEY_ROTATE_KIND_ROTATION) throw new LpParseError('bad-header');
  const durable = r.readFixed(FP_LEN);
  const priorEpoch = r.readU64();
  const successorEpoch = r.readU64();
  const newFp = r.readFixed(FP_LEN);
  const nextCommit = r.readFixed(FP_LEN);
  const armored = r.readLpUtf8(KEY_ROTATE_ARMORED_MAX);
  if (!isArmoredPublicKeyShape(armored)) throw new LpParseError('bad-field');
  const kem = r.readFixed(KEM_PUB_LEN);
  const dsaPub = r.readFixed(DSA_PUB_LEN);
  const authEd = r.readFixed(ED_PUB_LEN);
  const authDsa = r.readFixed(DSA_PUB_LEN);
  const sig = r.readFixed(ED_SIG_LEN + DSA_SIG_LEN);
  r.finish();
  const input: RotationSuccessorInput = {
    durable_id: bytesToHex(durable),
    prior_epoch: priorEpoch,
    successor_epoch: successorEpoch,
    new_fingerprint: bytesToHex(newFp),
    new_public_key: armored,
    new_pq_kem_public_key: uint8ToBase64(kem),
    new_pq_sig_public_key: uint8ToBase64(dsaPub),
    next_authority_commitment: bytesToHex(nextCommit),
    auth: {
      kind: 'rotation',
      auth_pubkeys: { sign: bytesToHex(authEd), pq_sig: bytesToHex(authDsa) },
      sig_by_authority: bytesToHex(sig),
    },
  };
  assertCanonical(input, bytes);
  return UnverifiedKeyRotate.__make(input);
}

/** The armored key is plain ASCII (newline and printable only) between the standard header and footer: no BOM, no CR, nothing that two byte strings could share. */
const ARMOR_HEAD = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const ARMOR_FOOT = '-----END PGP PUBLIC KEY BLOCK-----';
function isArmoredPublicKeyShape(s: string): boolean {
  if (!s.startsWith(ARMOR_HEAD)) return false;
  if (!(s.endsWith(ARMOR_FOOT) || s.endsWith(ARMOR_FOOT + '\n'))) return false;
  return /^[\n\x20-\x7e]*$/.test(s);
}

/** @internal The parsed object must encode back to EXACTLY the bytes it came from: one byte string per meaning. */
export function assertCanonical(input: RotationSuccessorInput, bytes: Uint8Array): void {
  let again: Uint8Array;
  try {
    again = encodeKeyRotate(input);
  } catch {
    throw new LpParseError('non-canonical');
  }
  if (again.length !== bytes.length) throw new LpParseError('non-canonical');
  for (let i = 0; i < again.length; i++) if (again[i] !== bytes[i]) throw new LpParseError('non-canonical');
}
