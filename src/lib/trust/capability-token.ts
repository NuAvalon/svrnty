// src/lib/trust/capability-token.ts
//
// T4 — client capability-token ISSUANCE + PRESENTATION (svrnty C-build, Lane C / Apollo).
//
// This is the CLIENT half of the blind mailbox-admission capability (Flint's X1, KB#90997). It replaces
// the central `allowed_senders` identity-gate: instead of the satellite deciding who may deposit, the
// RECIPIENT (A) hands each contact (B) a capability at card-exchange, and B presents it on every send.
// The satellite verifies the capability BLINDLY — it holds only A's per-(mailbox,epoch) admission PUBKEY,
// so it can verify but CANNOT MINT admissions (survive-without-us: a compromised relay can't fabricate
// senders). See the Python side: satellite `verify_capability` (Athena, Lane S2) — byte-identical to this.
//
// ── BYTE-EXACT SPEC (Flint X1 #150951 + review #151122; converged w/ Athena #151095) ──────────────────
//   scope       = `svrnty-cap:{mailbox_id}:{op_type}:{epoch}`
//                   FLAG-1 (Flint): mailbox_id = canonical lowercase-hex · op_type = CLOSED ENUM
//                   · epoch = non-negative int.  Keeps the `:`-delimited scope injective (no field holds ':').
//   issuer_cert = Ed25519(A_admit_sk[mailbox,epoch],  utf8(scope) ‖ holder_pub[32])   — A → B at card-exchange
//   nonce       = u32_be(unix_sec)[4] ‖ random[4]   (8 bytes)
//                   FLAG-2 (Flint, REQUIRED): the random tail makes each presentation UNIQUE. Ed25519 is
//                   deterministic, so a timestamp-only nonce would let a captured X-Capability REPLAY within
//                   the ±WINDOW (identical valid bytes). Satellite reads unix from nonce[:4] for the WINDOW
//                   check and DEDUPs the full 8-byte nonce within the window → replay closed, bursts allowed.
//   holder_fresh= Ed25519(holder_sk,  utf8(scope) ‖ nonce[8])   — B signs fresh on each send (±window anti-replay)
//   presentation= LP(issuer_cert) ‖ LP(holder_fresh) ‖ LP(holder_pub) ‖ LP(nonce)   (framing: see FRAMING note)
//   wire        = `{epoch}:{op_type}:base64(presentation)`   (the X-Capability header value)
//
//   Both signed preimages are injective on their own (fixed-length 32B/8B suffixes), so NO framing lives
//   inside a signature — the framing below is purely wire-packing so the satellite can split the 4 fields.
//
// ── FRAMING (pending Flint's domain call, ☀7484) ──────────────────────────────────────────────────────
//   Default here = u16-be length prefix per field (Flint blessed #151122; converged w/ Athena #151095):
//   injective, trivially split in both TS and the Python satellite, envelope byte-identical when (c)'s
//   variable-length blind-sig serials swap in. It is DISTINCT from lp-tlv.ts (uint32_be, client-only crypto)
//   and sign-envelope.ts (decimal-colon netstring, cross-language SIGNED objects). If Flint prefers the
//   cross-language netstring for this Python-verified path, swap `packPresentation`/`unpackPresentation`
//   only — the crypto above is framing-independent.
//
// CLAIM LADDER (Flint/Archie): v1 (b') is verifiable-not-mintable but LINKABLE (holder_pub is visible → the
//   satellite can correlate a mailbox's writers within an epoch). Honest claim = "subpoena-minimal", NEVER
//   "social-graph-private" until the (c) blind-credential swap ships (no holder_pub → unlinkable). Epoch
//   rotation bounds the linkage window.

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// ── FLAG-1: op_type is a CLOSED ENUM (never free-form) ────────────────────────────────────────────────
export const CAP_OP_TYPES = ['deposit', 'psi-initiate'] as const;
export type CapOpType = (typeof CAP_OP_TYPES)[number];

const MAILBOX_ID_RE = /^[0-9a-f]+$/; // canonical lowercase-hex
const ISSUER_CERT_LEN = 64;
const HOLDER_FRESH_LEN = 64;
const HOLDER_PUB_LEN = 32;
const NONCE_LEN = 8;

/**
 * The scope string, byte-exact. Fail-closed on any FLAG-1 violation — a scope that could contain ':' or a
 * non-enum op_type would break the injectivity the satellite relies on when it re-derives + cross-checks.
 */
export function capScope(mailboxId: string, opType: CapOpType, epoch: number): string {
  if (!MAILBOX_ID_RE.test(mailboxId))
    throw new Error(`capScope: mailbox_id must be canonical lowercase-hex, got ${JSON.stringify(mailboxId)}`);
  if (!CAP_OP_TYPES.includes(opType))
    throw new Error(`capScope: op_type not in enum {${CAP_OP_TYPES.join(', ')}}, got ${JSON.stringify(opType)}`);
  if (!Number.isInteger(epoch) || epoch < 0)
    throw new Error(`capScope: epoch must be a non-negative integer, got ${epoch}`);
  return `svrnty-cap:${mailboxId}:${opType}:${epoch}`;
}

// ── Per-(mailbox, epoch) admission keypair ────────────────────────────────────────────────────────────
// A generates one per mailbox per epoch, registers ONLY admitPub with the satellite (verify-not-mint),
// rotates it each epoch (revocation = don't re-issue to a revoked holder next epoch).
export interface AdmitKeypair {
  admitSk: Uint8Array; // 32B Ed25519 seed — IN-MEMORY / owner-vault only, NEVER sent to the satellite
  admitPub: Uint8Array; // 32B — registered with the satellite for {mailbox_id, epoch}
}

export function generateAdmitKeypair(): AdmitKeypair {
  const admitSk = ed25519.utils.randomPrivateKey();
  return { admitSk, admitPub: ed25519.getPublicKey(admitSk) };
}

// ── ISSUANCE (recipient A → holder B, at card-exchange) ───────────────────────────────────────────────
/** issuer_cert = Ed25519(A_admit_sk, utf8(scope) ‖ holder_pub). Reusable (issued once); freshness is in holder_fresh. */
export function issueCapability(
  admitSk: Uint8Array,
  mailboxId: string,
  opType: CapOpType,
  epoch: number,
  holderPub: Uint8Array,
): Uint8Array {
  if (holderPub.length !== HOLDER_PUB_LEN) throw new Error(`issueCapability: holder_pub must be ${HOLDER_PUB_LEN}B`);
  const scope = capScope(mailboxId, opType, epoch);
  return ed25519.sign(concatBytes(utf8ToBytes(scope), holderPub), admitSk);
}

// ── PRESENTATION (holder B, on every send) ────────────────────────────────────────────────────────────
/** FLAG-2 nonce = u32_be(unix_sec) ‖ random[4]. Satellite reads unix from nonce[:4] (WINDOW) + dedups full nonce. */
export function makeNonce(unixSec: number): Uint8Array {
  if (!Number.isInteger(unixSec) || unixSec < 0 || unixSec > 0xffffffff)
    throw new Error(`makeNonce: unix_sec must fit u32, got ${unixSec}`);
  const n = new Uint8Array(NONCE_LEN);
  new DataView(n.buffer).setUint32(0, unixSec, false); // big-endian
  n.set(randomBytes(4), 4);
  return n;
}

/**
 * Build the X-Capability header value: sign a fresh holder_fresh and pack the presentation.
 * @returns `{epoch}:{op_type}:base64(presentation)`
 */
export function presentCapability(params: {
  holderSk: Uint8Array;
  holderPub: Uint8Array;
  issuerCert: Uint8Array;
  mailboxId: string;
  opType: CapOpType;
  epoch: number;
  unixSec: number;
  nonce?: Uint8Array; // test hook (deterministic vectors); production omits → random
}): string {
  const { holderSk, holderPub, issuerCert, mailboxId, opType, epoch, unixSec } = params;
  if (issuerCert.length !== ISSUER_CERT_LEN) throw new Error(`presentCapability: issuer_cert must be ${ISSUER_CERT_LEN}B`);
  if (holderPub.length !== HOLDER_PUB_LEN) throw new Error(`presentCapability: holder_pub must be ${HOLDER_PUB_LEN}B`);
  const scope = capScope(mailboxId, opType, epoch);
  const nonce = params.nonce ?? makeNonce(unixSec);
  if (nonce.length !== NONCE_LEN) throw new Error(`presentCapability: nonce must be ${NONCE_LEN}B`);
  const holderFresh = ed25519.sign(concatBytes(utf8ToBytes(scope), nonce), holderSk);
  const presentation = packPresentation([issuerCert, holderFresh, holderPub, nonce]);
  return `${epoch}:${opType}:${toBase64(presentation)}`;
}

// ── VERIFY (mirror of the satellite's authoritative verify_capability — for tests + the co-verify vector) ─
// The satellite (Athena) is authoritative: it owns admit_pubkey lookup by {mailbox_id, epoch}, the WINDOW
// clock, and the per-mailbox within-window dedup set. This mirror lets us self-test the crypto and emit the
// shared S5/T6 co-verify vector; both sides MUST agree byte-for-byte.
export interface CapVerifyInput {
  header: string; // the X-Capability header value
  mailboxId: string; // route target — cross-check #2 (cap bound to THIS mailbox)
  admitPub: Uint8Array; // A's registered per-(mailbox,epoch) admission pubkey — cross-check #3
  nowUnixSec: number;
  windowSec?: number; // Athena's WINDOW knob (default ±60)
  seenNonces?: Set<string>; // per-mailbox within-window dedup (hex nonces) — FLAG-2 replay guard
}
export interface CapVerifyResult {
  ok: boolean;
  reason?: string;
  holderPub?: Uint8Array;
  nonceHex?: string;
  unixSec?: number;
}

export function verifyCapability(inp: CapVerifyInput): CapVerifyResult {
  const windowSec = inp.windowSec ?? 60;
  const parts = inp.header.split(':');
  if (parts.length !== 3) return { ok: false, reason: 'bad-header-shape' };
  const [epochStr, opType, b64] = parts;
  const epoch = Number(epochStr);
  if (!Number.isInteger(epoch) || epoch < 0 || String(epoch) !== epochStr) return { ok: false, reason: 'bad-epoch' };
  if (!CAP_OP_TYPES.includes(opType as CapOpType)) return { ok: false, reason: 'bad-op-type' }; // FLAG-1

  let presentation: Uint8Array;
  try {
    presentation = fromBase64(b64);
  } catch {
    return { ok: false, reason: 'bad-base64' };
  }
  let fields: Uint8Array[];
  try {
    fields = unpackPresentation(presentation, 4);
  } catch {
    return { ok: false, reason: 'bad-framing' };
  }
  const [issuerCert, holderFresh, holderPub, nonce] = fields;
  if (
    issuerCert.length !== ISSUER_CERT_LEN ||
    holderFresh.length !== HOLDER_FRESH_LEN ||
    holderPub.length !== HOLDER_PUB_LEN ||
    nonce.length !== NONCE_LEN
  )
    return { ok: false, reason: 'bad-field-lengths' };

  // cross-check #1 (header==signed-scope) + #2 (mailbox_id==route target): we rebuild scope from the ROUTE
  // mailbox_id + the header's epoch/op_type, so both are enforced structurally (a cap signed for another
  // mailbox/op/epoch won't verify against this rebuilt scope).
  let scope: string;
  try {
    scope = capScope(inp.mailboxId, opType as CapOpType, epoch);
  } catch {
    return { ok: false, reason: 'bad-scope-fields' };
  }
  // issuer_cert vs A's admission pubkey (verify-not-mint) — cross-check #3 is the caller looking up admitPub.
  if (!ed25519.verify(issuerCert, concatBytes(utf8ToBytes(scope), holderPub), inp.admitPub))
    return { ok: false, reason: 'issuer_cert-invalid' };
  // holder_fresh vs holder_pub
  if (!ed25519.verify(holderFresh, concatBytes(utf8ToBytes(scope), nonce), holderPub))
    return { ok: false, reason: 'holder_fresh-invalid' };

  // FLAG-2 WINDOW: unix from nonce[:4]
  const nonceUnix = new DataView(nonce.buffer, nonce.byteOffset, NONCE_LEN).getUint32(0, false);
  if (Math.abs(inp.nowUnixSec - nonceUnix) > windowSec) return { ok: false, reason: 'window' };
  // FLAG-2 dedup: reject replay within window
  const nonceHex = bytesToHex(nonce);
  if (inp.seenNonces) {
    if (inp.seenNonces.has(nonceHex)) return { ok: false, reason: 'replay' };
    inp.seenNonces.add(nonceHex);
  }
  return { ok: true, holderPub, nonceHex, unixSec: nonceUnix };
}

// ── FRAMING (isolated — swap these two if Flint picks the netstring; crypto above is unaffected) ─────────
// u16-be length prefix per field. Injective (fixed-width prefix, no delimiter parse) + rejects trailing bytes.
function u16be(n: number): Uint8Array {
  if (n < 0 || n > 0xffff) throw new Error(`u16be: out of range ${n}`);
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, false);
  return b;
}

export function packPresentation(fields: Uint8Array[]): Uint8Array {
  return concatBytes(...fields.flatMap((f) => [u16be(f.length), f]));
}

export function unpackPresentation(buf: Uint8Array, count: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  let o = 0;
  for (let i = 0; i < count; i++) {
    if (o + 2 > buf.length) throw new Error('unpackPresentation: truncated length prefix');
    const len = new DataView(buf.buffer, buf.byteOffset + o, 2).getUint16(0, false);
    o += 2;
    if (o + len > buf.length) throw new Error('unpackPresentation: truncated field');
    out.push(buf.subarray(o, o + len));
    o += len;
  }
  if (o !== buf.length) throw new Error('unpackPresentation: trailing bytes (non-injective input)');
  return out;
}

// ── base64 (portable: btoa/atob are global in browsers and Node ≥16) ────────────────────────────────────
function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
