// src/lib/trust/pointer-v2-wire.ts
/**
 * Mailbox POINTER v2: the bytes of "here is my current mailbox" (task #809, step 2). DARK: nothing in the app imports this module.
 * Pure bytes in, bytes out, plus one typed gate. No I/O, no clock, no randomness, no secret keys (signing is the caller's; this module only
 * names the bytes that are signed and checks signatures).
 *
 * A signed object, in the form the reviewers pinned: STRICT lengths, NO trailing bytes, a refusal never echoes attacker bytes, and NO parsed
 * field is used before BOTH signature halves verify. `parsePointerV2` returns an `UnverifiedPointerV2` that exposes nothing; its only method,
 * `verify`, returns the fields only after the identity signature (Ed25519 AND ML-DSA-87, both required, cheap half first, no fallback) and, when
 * the pointer carries one, the authority signature have verified.
 *
 * Layout (integers big-endian):
 *   prefix (this is what is signed, after a domain tag)
 *     'M' 'P' version(0x02) flags(1)     flags bit0 = an authority block follows the identity signature; other bits must be 0
 *     mailbox_id            32   the v2 mailbox id, raw (sha256 over the mailbox auth keys)
 *     relay                 LP   https origin, ASCII, at most 255 bytes
 *     identity_epoch        8    u64
 *     pointer_epoch         8    u64
 *     x25519_pub            32   device-mailbox seal key
 *     mlkem1024_ek          1568 device-mailbox seal key
 *   identity signature      64 + 4627   Ed25519 then ML-DSA-87 over  LP(domain) || LP(prefix)
 *   authority block (only if flags bit0)
 *     authority ed25519 public key 32, authority ML-DSA-87 public key 2592   (their hash must equal the receiver's pinned commitment)
 *     authority signature   64 + 4627   over  LP(authority domain) || LP(prefix)
 * The flag is INSIDE the signed prefix, so stripping the authority block cannot be done without invalidating the identity signature: a stripped
 * pointer is a different, identity-only claim. Whether an identity-only pointer may be accepted (it may not name a new relay) is the receive
 * function's rule, not this module's.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { LpReader, LpParseError } from '../crypto/lp-reader';
import { lpBin, lpStr, u64be } from '../crypto/lp-tlv';
import { ownerAuthorityCommitment } from '../crypto/owner-authority-commitment';

export const POINTER_V2_MAGIC = Uint8Array.of(0x4d, 0x50); // 'MP'
export const POINTER_V2_VERSION = 0x02;
export const POINTER_V2_DOMAIN = 'svrnty:mailbox-ptr:v2';
export const POINTER_V2_AUTHORITY_DOMAIN = 'svrnty:mailbox-ptr-authority:v2';
export const POINTER_V2_RELAY_MAX = 255;

const FLAG_AUTHORITY = 0x01;
const ID_LEN = 32;
const X25519_LEN = 32;
const KEM_LEN = 1568;
const ED_PUB = 32;
const DSA_PUB = 2592;
const ED_SIG = 64;
const DSA_SIG = 4627;
/**
 * One canonical spelling per origin, so string equality means "the same relay". A plain https origin only: lower-case host of at least two
 * labels (1-63 characters, letters, digits and inner hyphens, no empty label), whose last label contains a letter (so no IP literal) and
 * is not 'localhost'; an optional explicit port 1-65535 with no leading zero and never 443 (the default is spelled by leaving it out);
 * no userinfo, path, query or fragment. Where the name RESOLVES (a private or loopback address) is a connect-time rule, not a byte rule.
 */
export function isCanonicalRelayOrigin(s: unknown): s is string {
  if (typeof s !== 'string' || s.length > POINTER_V2_RELAY_MAX || !s.startsWith('https://')) return false;
  const rest = s.slice('https://'.length);
  const m = /^([a-z0-9.-]+)(?::([0-9]+))?$/.exec(rest);
  if (!m) return false;
  const host = m[1];
  if (host.length > 253) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  for (const l of labels) {
    if (l.length < 1 || l.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(l)) return false;
  }
  if (!/[a-z]/.test(labels[labels.length - 1])) return false;
  if (host === 'localhost' || host.endsWith('.localhost')) return false;
  if (m[2] !== undefined) {
    if (!/^[1-9][0-9]{0,4}$/.test(m[2])) return false;
    const port = Number(m[2]);
    if (port > 65535 || port === 443) return false;
  }
  return true;
}

export class PointerV2Refused extends Error {
  constructor(public readonly reason: string) {
    super(`pointer v2 refused (${reason})`);
    this.name = 'PointerV2Refused';
  }
}

export interface PointerV2Fields {
  /** 32 raw bytes of the v2 mailbox id (the id is 'mbx2_' + hex of these). */
  mailboxId: Uint8Array;
  relay: string;
  identityEpoch: number;
  pointerEpoch: number;
  x25519Pub: Uint8Array;
  mlkem1024Ek: Uint8Array;
  /** true if an authority block will follow (it is part of what is signed). */
  hasAuthority: boolean;
}

export interface HybridSig { ed: Uint8Array; dsa: Uint8Array }
export interface AuthorityBlock { edPublic: Uint8Array; dsaPublic: Uint8Array; sig: HybridSig }

const concat = (parts: Uint8Array[]): Uint8Array => {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const exact = (b: unknown, n: number, what: string): Uint8Array => {
  if (!(b instanceof Uint8Array) || b.length !== n) throw new PointerV2Refused(`bad-${what}`);
  return b;
};
const epochOk = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;

/** The signed prefix. Throws PointerV2Refused on any field of the wrong shape. */
export function pointerV2Prefix(f: PointerV2Fields): Uint8Array {
  if (!isCanonicalRelayOrigin(f.relay)) throw new PointerV2Refused('bad-relay');
  if (!epochOk(f.identityEpoch) || !epochOk(f.pointerEpoch)) throw new PointerV2Refused('bad-epoch');
  return concat([
    POINTER_V2_MAGIC,
    Uint8Array.of(POINTER_V2_VERSION, f.hasAuthority ? FLAG_AUTHORITY : 0),
    exact(f.mailboxId, ID_LEN, 'mailbox-id'),
    lpStr(f.relay),
    u64be(f.identityEpoch),
    u64be(f.pointerEpoch),
    exact(f.x25519Pub, X25519_LEN, 'x25519'),
    exact(f.mlkem1024Ek, KEM_LEN, 'mlkem'),
  ]);
}

/** The exact bytes each signature covers: LP(domain) || LP(prefix). */
export const pointerV2SigningInput = (prefix: Uint8Array, authority: boolean): Uint8Array =>
  concat([lpStr(authority ? POINTER_V2_AUTHORITY_DOMAIN : POINTER_V2_DOMAIN), lpBin(prefix)]);

const sigBytes = (s: HybridSig): Uint8Array => concat([exact(s.ed, ED_SIG, 'sig'), exact(s.dsa, DSA_SIG, 'sig')]);

/** Assemble a pointer from its fields and ready-made signatures (made by the caller over pointerV2SigningInput). */
export function encodePointerV2(f: PointerV2Fields, identitySig: HybridSig, authority?: AuthorityBlock): Uint8Array {
  if (f.hasAuthority !== (authority !== undefined)) throw new PointerV2Refused('authority-flag-mismatch');
  const parts = [pointerV2Prefix(f), sigBytes(identitySig)];
  if (authority) parts.push(exact(authority.edPublic, ED_PUB, 'authority-key'), exact(authority.dsaPublic, DSA_PUB, 'authority-key'), sigBytes(authority.sig));
  return concat(parts);
}

// Parsed values live in a module-private map keyed by the opaque object: there is no property to read.
interface Parsed {
  fields: PointerV2Fields;
  prefix: Uint8Array;
  identitySig: HybridSig;
  authority?: AuthorityBlock;
}
const PARSED = new WeakMap<object, Parsed>();

export interface PointerV2Verifiers {
  edVerify: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => boolean;
  dsaVerify: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => boolean;
}
const NOBLE: PointerV2Verifiers = {
  edVerify: (sig, msg, pub) => ed25519.verify(sig, msg, pub),
  dsaVerify: (sig, msg, pub) => ml_dsa87.verify(sig, msg, pub),
};

export interface PointerV2VerifyDeps {
  /** The publisher's identity public keys, held by the receiver (never read from the pointer). */
  identity: { edPublic: Uint8Array; dsaPublic: Uint8Array };
  /** The receiver's pinned OWNER-authority commitment (ownerAuthorityCommitment: 64 lowercase hex; NOT the rotation commitment). Required only if the pointer carries an authority block. */
  authorityPin?: string;
  /** Test seam: the two verification primitives. */
  verifiers?: PointerV2Verifiers;
}

export interface VerifiedPointerV2 {
  readonly mailboxId: string; // 'mbx2_' + 64 hex
  readonly relay: string;
  readonly identityEpoch: number;
  readonly pointerEpoch: number;
  readonly x25519Pub: Uint8Array;
  readonly mlkem1024Ek: Uint8Array;
  readonly authoritySigned: boolean;
}

function hybridOk(v: PointerV2Verifiers, sig: HybridSig, msg: Uint8Array, edPub: Uint8Array, dsaPub: Uint8Array): boolean {
  // Cheap half first. A failed half is a rejection: there is NO fallback to the other half alone.
  try {
    if (!v.edVerify(sig.ed, msg, edPub)) return false;
    return v.dsaVerify(sig.dsa, msg, dsaPub) === true;
  } catch {
    return false;
  }
}

export class UnverifiedPointerV2 {
  private constructor() {}

  /** @internal */
  static __make(p: Parsed): UnverifiedPointerV2 {
    const o = new UnverifiedPointerV2();
    PARSED.set(o, p);
    return o;
  }

  /** Check every signature. Nothing is returned unless all of them verify. */
  verify(deps: PointerV2VerifyDeps): VerifiedPointerV2 {
    const p = PARSED.get(this);
    if (!p) throw new PointerV2Refused('no-fields');
    const v = deps.verifiers ?? NOBLE;
    const id = deps.identity;
    if (!id || !(id.edPublic instanceof Uint8Array) || id.edPublic.length !== ED_PUB || !(id.dsaPublic instanceof Uint8Array) || id.dsaPublic.length !== DSA_PUB) {
      throw new PointerV2Refused('bad-identity-key');
    }
    if (!hybridOk(v, p.identitySig, pointerV2SigningInput(p.prefix, false), id.edPublic, id.dsaPublic)) throw new PointerV2Refused('bad-identity-sig');
    let authoritySigned = false;
    if (p.authority) {
      const pin = deps.authorityPin;
      if (typeof pin !== 'string' || !/^[0-9a-f]{64}$/.test(pin)) throw new PointerV2Refused('no-authority-pin');
      if (ownerAuthorityCommitment(p.authority.edPublic, p.authority.dsaPublic) !== pin) throw new PointerV2Refused('authority-pin-mismatch');
      if (!hybridOk(v, p.authority.sig, pointerV2SigningInput(p.prefix, true), p.authority.edPublic, p.authority.dsaPublic)) throw new PointerV2Refused('bad-authority-sig');
      authoritySigned = true;
    }
    const f = p.fields;
    return Object.freeze({
      mailboxId: 'mbx2_' + bytesToHex(f.mailboxId),
      relay: f.relay,
      identityEpoch: f.identityEpoch,
      pointerEpoch: f.pointerEpoch,
      x25519Pub: f.x25519Pub.slice(),
      mlkem1024Ek: f.mlkem1024Ek.slice(),
      authoritySigned,
    });
  }
}

/** Parse a pointer v2. Strict; throws LpParseError (a reason code only). The result exposes nothing until verified. */
export function parsePointerV2(bytes: Uint8Array): UnverifiedPointerV2 {
  const r = new LpReader(bytes);
  const magic = r.readFixed(2);
  if (magic[0] !== POINTER_V2_MAGIC[0] || magic[1] !== POINTER_V2_MAGIC[1]) throw new LpParseError('bad-header');
  if (r.readU8() !== POINTER_V2_VERSION) throw new LpParseError('bad-header');
  const flags = r.readU8();
  if ((flags & ~FLAG_AUTHORITY) !== 0) throw new LpParseError('bad-header');
  const mailboxId = r.readFixed(ID_LEN);
  const relay = r.readLpUtf8(POINTER_V2_RELAY_MAX);
  if (!isCanonicalRelayOrigin(relay)) throw new LpParseError('bad-field');
  const identityEpoch = r.readU64();
  const pointerEpoch = r.readU64();
  const x25519Pub = r.readFixed(X25519_LEN);
  const mlkem1024Ek = r.readFixed(KEM_LEN);
  const hasAuthority = (flags & FLAG_AUTHORITY) !== 0;
  const fields: PointerV2Fields = { mailboxId, relay, identityEpoch, pointerEpoch, x25519Pub, mlkem1024Ek, hasAuthority };
  const prefix = r.consumed(); // from the reader's own copy: what is signed is what was parsed, whatever the caller does with its buffer
  const identitySig: HybridSig = { ed: r.readFixed(ED_SIG), dsa: r.readFixed(DSA_SIG) };
  let authority: AuthorityBlock | undefined;
  if (hasAuthority) {
    authority = { edPublic: r.readFixed(ED_PUB), dsaPublic: r.readFixed(DSA_PUB), sig: { ed: r.readFixed(ED_SIG), dsa: r.readFixed(DSA_SIG) } };
  }
  r.finish();
  assertCanonicalPointerV2(fields, identitySig, authority, r.snapshot());
  return UnverifiedPointerV2.__make({ fields, prefix, identitySig, authority });
}

/** @internal The parsed object must encode back to EXACTLY the bytes it came from. */
export function assertCanonicalPointerV2(f: PointerV2Fields, idSig: HybridSig, authority: AuthorityBlock | undefined, bytes: Uint8Array): void {
  let again: Uint8Array;
  try { again = encodePointerV2(f, idSig, authority); } catch { throw new LpParseError('non-canonical'); }
  if (again.length !== bytes.length) throw new LpParseError('non-canonical');
  for (let i = 0; i < again.length; i++) if (again[i] !== bytes[i]) throw new LpParseError('non-canonical');
}
