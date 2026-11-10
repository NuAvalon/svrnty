// src/lib/trust/approve-wire.ts — task #810: the APPROVE record, bytes and gate (D2 v1.6 "APPROVE wire form").
/**
 * DARK and PURE: nothing imports this yet; no I/O, no clock, no randomness, no secret keys (signing is the caller's; this module names the
 * bytes that are signed and checks signatures). Same bar as pointer v2: strict widths, no trailing bytes, a refusal is a reason code and never
 * any part of the input, and `parseApprove` returns an object that exposes NOTHING until `verify` has passed every step.
 *
 * One record carrying BOTH the owner-authority signature and the identity-key signature. It waives W and supersedes a pending attempt. It is
 * SELF-CONTAINED: the whole approved object rides inside, so junk in the pending slots cannot crowd it out.
 *
 * Layout (integers big-endian, raw keys and signatures fixed-length and unframed, LP = u32 length then bytes), nothing after the record:
 *   'A' 'P' | version 0x01
 *   body   = kind u8 | durable_id 32 | identity_epoch u64 | LP(claim_digest, 32 bytes)
 *   LP(subject)                    the approved object's full wire bytes, at most 32768
 *   authority keys                 Ed25519 32 | ML-DSA-87 2592
 *   identity signature             Ed25519 64 | ML-DSA-87 4627
 *   authority signature            Ed25519 64 | ML-DSA-87 4627
 * kind 1 = relay move (subject = an AUTHORITY-signed pointer v2). Kinds 2 (guardian set) and 3 (master rotation) are RESERVED and refused
 * until their subject formats exist; any other value is refused.
 * Signing inputs, role-separated: LP("svrnty:approve:identity:v1") || LP(body) and LP("svrnty:approve:authority:v1") || LP(body).
 *
 * Verify order (a throw is a refusal; nothing past a failed step runs): known kind and exact lengths (parse) -> durable id and epoch against
 * what the receiver HOLDS -> the authority keys open the held owner-authority pin (no pin held = refuse) -> identity signature with the HELD
 * identity keys (never keys from the record), then the authority signature with the record's authority keys, both halves each, cheap half
 * first -> the subject fully verified by its own verifier, and it MUST carry an authority block and the same identity epoch -> the recomputed
 * claim digest equals the one in the body.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { LpReader, LpParseError } from '../crypto/lp-reader';
import { lpBin, lpStr, u64be } from '../crypto/lp-tlv';
import { ownerAuthorityCommitment } from '../crypto/owner-authority-commitment';
import { parsePointerV2, type VerifiedPointerV2, type HybridSig } from './pointer-v2-wire';
import { pointerClaimDigest } from './claim-digest';

export const APPROVE_MAGIC = Uint8Array.of(0x41, 0x50); // 'AP'
export const APPROVE_VERSION = 0x01;
export const APPROVE_KIND_RELAY_MOVE = 1;
export const APPROVE_SUBJECT_MAX = 32768;
export const APPROVE_DOMAIN_IDENTITY = 'svrnty:approve:identity:v1';
export const APPROVE_DOMAIN_AUTHORITY = 'svrnty:approve:authority:v1';

const ID_LEN = 32;
const DIGEST_LEN = 32;
const ED_PUB = 32;
const DSA_PUB = 2592;
const ED_SIG = 64;
const DSA_SIG = 4627;

export class ApproveRefused extends Error {
  constructor(public readonly reason: string) {
    super('approve refused (' + reason + ')'); // a reason code only, never input
    this.name = 'ApproveRefused';
  }
}

export interface ApproveFields {
  readonly kind: number;
  /** The DID anchor, 32 raw bytes. */
  readonly durableId: Uint8Array;
  readonly identityEpoch: number;
  /** SHA-256 of the SUBJECT's signed claim, 32 raw bytes. */
  readonly claimDigest: Uint8Array;
  /** The approved object's full wire bytes. */
  readonly subject: Uint8Array;
}
export interface ApproveAuthorityKeys { readonly edPublic: Uint8Array; readonly dsaPublic: Uint8Array }

const concat = (parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const exact = (b: unknown, n: number, what: string): Uint8Array => {
  if (!(b instanceof Uint8Array) || b.length !== n) throw new ApproveRefused('bad-' + what);
  return b;
};
const epochOk = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;

/** The bytes both signatures cover (inside the domain): kind || durable_id || u64 identity_epoch || LP(claim_digest). */
export function approveBody(f: ApproveFields): Uint8Array {
  if (f.kind !== APPROVE_KIND_RELAY_MOVE) throw new ApproveRefused('bad-kind'); // 2 and 3 are reserved, anything else is unknown
  if (!epochOk(f.identityEpoch)) throw new ApproveRefused('bad-epoch');
  return concat([Uint8Array.of(f.kind), exact(f.durableId, ID_LEN, 'durable-id'), u64be(f.identityEpoch), lpBin(exact(f.claimDigest, DIGEST_LEN, 'claim-digest'))]);
}

/** The exact bytes a signature of that role covers: LP(domain) || LP(body). */
export const approveSigningInput = (body: Uint8Array, role: 'identity' | 'authority'): Uint8Array =>
  concat([lpStr(role === 'identity' ? APPROVE_DOMAIN_IDENTITY : APPROVE_DOMAIN_AUTHORITY), lpBin(body)]);

const sigBytes = (s: HybridSig): Uint8Array => concat([exact(s.ed, ED_SIG, 'sig'), exact(s.dsa, DSA_SIG, 'sig')]);

/** Assemble a record from its fields and ready-made signatures (made by the caller over approveSigningInput). */
export function encodeApprove(f: ApproveFields, authorityKeys: ApproveAuthorityKeys, identitySig: HybridSig, authoritySig: HybridSig): Uint8Array {
  if (!(f.subject instanceof Uint8Array) || f.subject.length > APPROVE_SUBJECT_MAX) throw new ApproveRefused('bad-subject');
  return concat([
    APPROVE_MAGIC, Uint8Array.of(APPROVE_VERSION),
    approveBody(f),
    lpBin(f.subject),
    exact(authorityKeys.edPublic, ED_PUB, 'authority-key'), exact(authorityKeys.dsaPublic, DSA_PUB, 'authority-key'),
    sigBytes(identitySig), sigBytes(authoritySig),
  ]);
}

interface Parsed {
  fields: ApproveFields;
  body: Uint8Array;
  authorityKeys: ApproveAuthorityKeys;
  identitySig: HybridSig;
  authoritySig: HybridSig;
}
// Parsed values live in a module-private map keyed by the opaque object: there is no property to read.
const PARSED = new WeakMap<object, Parsed>();

export interface ApproveVerifiers {
  edVerify: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => boolean;
  dsaVerify: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => boolean;
}
const NOBLE: ApproveVerifiers = {
  edVerify: (sig, msg, pub) => ed25519.verify(sig, msg, pub),
  dsaVerify: (sig, msg, pub) => ml_dsa87.verify(sig, msg, pub),
};

export interface ApproveVerifyDeps {
  /** What the receiver HOLDS for this contact. Nothing here is read from the record. */
  held: {
    /** The DID anchor, 64 lowercase hex. */
    durableId: string;
    identityEpoch: number;
    identityKeys: { edPublic: Uint8Array; dsaPublic: Uint8Array };
    /** The owner-authority commitment (ownerAuthorityCommitment). Absent = a pre-feature identity: nothing can be approved. */
    ownerAuthorityPin?: string;
  };
  /** Test seam: the two verification primitives (applied to the record's own signatures and, through the subject, to the pointer's). */
  verifiers?: ApproveVerifiers;
}

export interface VerifiedApprove {
  readonly kind: number;
  readonly durableId: string;
  readonly identityEpoch: number;
  /** 64 lowercase hex: the digest every other part of #810 names this claim by. */
  readonly claimDigest: string;
  /** The approved pointer, fully verified, authority-signed. */
  readonly pointer: VerifiedPointerV2;
}

function hybridOk(v: ApproveVerifiers, sig: HybridSig, msg: Uint8Array, edPub: Uint8Array, dsaPub: Uint8Array): boolean {
  // Cheap half first. A failed half is a rejection: there is NO fallback to the other half alone.
  try {
    if (!v.edVerify(sig.ed, msg, edPub)) return false;
    return v.dsaVerify(sig.dsa, msg, dsaPub) === true;
  } catch {
    return false;
  }
}
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

export class UnverifiedApprove {
  private constructor() {}

  /** @internal */
  static __make(p: Parsed): UnverifiedApprove {
    const o = new UnverifiedApprove();
    PARSED.set(o, p);
    return o;
  }

  /** Check everything, in the order of the header. Nothing is returned unless every step passes. */
  verify(deps: ApproveVerifyDeps): VerifiedApprove {
    const p = PARSED.get(this);
    if (!p) throw new ApproveRefused('no-fields');
    const v = deps.verifiers ?? NOBLE;
    const h = deps.held;
    if (!h || typeof h.durableId !== 'string' || !/^[0-9a-f]{64}$/.test(h.durableId) || !epochOk(h.identityEpoch)) throw new ApproveRefused('bad-held');
    if (!h.identityKeys || !(h.identityKeys.edPublic instanceof Uint8Array) || h.identityKeys.edPublic.length !== ED_PUB
      || !(h.identityKeys.dsaPublic instanceof Uint8Array) || h.identityKeys.dsaPublic.length !== DSA_PUB) throw new ApproveRefused('bad-identity-key');
    const f = p.fields;
    // 2. the durable id and the epoch against what we hold
    if (!sameBytes(f.durableId, hexToBytes(h.durableId))) throw new ApproveRefused('wrong-durable-id');
    if (f.identityEpoch < h.identityEpoch) throw new ApproveRefused('stale-identity-epoch');
    if (f.identityEpoch > h.identityEpoch) throw new ApproveRefused('identity-epoch-ahead'); // keys we do not hold yet: the caller writes nothing
    // 3. the authority keys open the held pin
    const pin = h.ownerAuthorityPin;
    if (typeof pin !== 'string' || !/^[0-9a-f]{64}$/.test(pin)) throw new ApproveRefused('no-authority-pin');
    if (ownerAuthorityCommitment(p.authorityKeys.edPublic, p.authorityKeys.dsaPublic) !== pin) throw new ApproveRefused('authority-pin-mismatch');
    // 4. identity signature with the HELD keys, then the authority signature with the record's authority keys
    if (!hybridOk(v, p.identitySig, approveSigningInput(p.body, 'identity'), h.identityKeys.edPublic, h.identityKeys.dsaPublic)) throw new ApproveRefused('bad-identity-sig');
    if (!hybridOk(v, p.authoritySig, approveSigningInput(p.body, 'authority'), p.authorityKeys.edPublic, p.authorityKeys.dsaPublic)) throw new ApproveRefused('bad-authority-sig');
    // 5. the subject, with its own verifier, fully; an identity-only pointer is never approved
    let pointer: VerifiedPointerV2;
    try {
      pointer = parsePointerV2(f.subject).verify({ identity: h.identityKeys, authorityPin: pin, verifiers: v });
    } catch {
      throw new ApproveRefused('bad-subject');
    }
    if (!pointer.authoritySigned) throw new ApproveRefused('subject-not-authority-signed');
    if (pointer.identityEpoch !== f.identityEpoch) throw new ApproveRefused('subject-epoch-mismatch');
    // 6. the recomputed claim digest equals the one the body names
    if (!sameBytes(pointerClaimDigest(pointer), f.claimDigest)) throw new ApproveRefused('claim-digest-mismatch');
    return Object.freeze({ kind: f.kind, durableId: h.durableId, identityEpoch: f.identityEpoch, claimDigest: bytesToHex(f.claimDigest), pointer });
  }
}

/** Parse an APPROVE record. Strict; throws LpParseError (a reason code only). The result exposes nothing until verified. */
export function parseApprove(bytes: Uint8Array): UnverifiedApprove {
  const r = new LpReader(bytes);
  const magic = r.readFixed(2);
  if (magic[0] !== APPROVE_MAGIC[0] || magic[1] !== APPROVE_MAGIC[1]) throw new LpParseError('bad-header');
  if (r.readU8() !== APPROVE_VERSION) throw new LpParseError('bad-header');
  const kind = r.readU8();
  if (kind !== APPROVE_KIND_RELAY_MOVE) throw new LpParseError('bad-field'); // 2 and 3 reserved, others unknown
  const durableId = r.readFixed(ID_LEN);
  const identityEpoch = r.readU64();
  const claimDigest = r.readLp(DIGEST_LEN);
  if (claimDigest.length !== DIGEST_LEN) throw new LpParseError('bad-field');
  const body = r.consumed().slice(APPROVE_MAGIC.length + 1); // from the reader's own copy: what is signed is what was parsed
  const subject = r.readLp(APPROVE_SUBJECT_MAX);
  const authorityKeys: ApproveAuthorityKeys = { edPublic: r.readFixed(ED_PUB), dsaPublic: r.readFixed(DSA_PUB) };
  const identitySig: HybridSig = { ed: r.readFixed(ED_SIG), dsa: r.readFixed(DSA_SIG) };
  const authoritySig: HybridSig = { ed: r.readFixed(ED_SIG), dsa: r.readFixed(DSA_SIG) };
  r.finish();
  const fields: ApproveFields = { kind, durableId, identityEpoch, claimDigest, subject };
  assertCanonicalApprove(fields, authorityKeys, identitySig, authoritySig, r.snapshot());
  return UnverifiedApprove.__make({ fields, body, authorityKeys, identitySig, authoritySig });
}

/** @internal The parsed object must encode back to EXACTLY the bytes it came from. */
export function assertCanonicalApprove(f: ApproveFields, keys: ApproveAuthorityKeys, idSig: HybridSig, authSig: HybridSig, bytes: Uint8Array): void {
  let again: Uint8Array;
  try { again = encodeApprove(f, keys, idSig, authSig); } catch { throw new LpParseError('non-canonical'); }
  if (!sameBytes(again, bytes)) throw new LpParseError('non-canonical');
}
