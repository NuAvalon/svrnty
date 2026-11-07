#!/usr/bin/env node
// #588 mutual-trust beacon: the centurion's poll / withdraw authenticator, run by the satellite as ONE subprocess per call.
//
//   node auth.mjs        stdin: {"op","H_e","N","K","pk","sig","nonce"}   (K = the K STORED for (H_e, N), from its proof)
//   exit 0 + exactly {"ok":true}\n = authenticated; exit 1 + {"ok":false,"reason":"wire"|"auth"} = refused; exit 2 = internal.
//
// Authenticated means ALL of: pk is a canonical Ed25519 point and not of small order; Poseidon(DS_K, pk_lo, pk_hi) == K (the
// inputs come from the ONE shared module the client imports, pinned by the KAT vector); S < L; and node:crypto verifies the
// signature over authMessage(op, H_e, N, nonce), which names the op. Every check runs whatever the others say, and any failure
// is the single reason "auth", so neither the reason nor the work done says which check failed.
// OpenSSL checks S < L but NOT the order of A (the identity as pk verifies a message-independent signature), hence the explicit
// small-order check. Mixed-order keys (prime-order point + torsion) are NOT refused: a standard key is never one, and only the
// key's owner can sign under it. No state, no network: nonce single-use and TTL are the caller's (one transaction with the action).
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import { AUTH_OPS, kInputs, authMessage, parseFieldElement, WireError } from '../../../src/lib/crypto/beacon-wire.mjs';

const MAX_STDIN = 4096;
const KEYS = ['op', 'H_e', 'N', 'K', 'pk', 'sig', 'nonce'];

class Refused extends Error {
  constructor(reason) { super(reason); this.reason = reason; }
}

// ---- Ed25519 point decoding and the small-order test (affine twisted Edwards, a = -1; BigInt, not constant-time: the
// inputs are public) ----
const p = 2n ** 255n - 19n;
/** The prime order of the Ed25519 base point. */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a) => ((a % p) + p) % p;
const pow = (b, e) => {
  let r = 1n;
  let x = mod(b);
  for (let k = e; k > 0n; k >>= 1n) {
    if (k & 1n) r = (r * x) % p;
    x = (x * x) % p;
  }
  return r;
};
const inv = (a) => pow(a, p - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (p - 1n) / 4n);

/** The 8 points of order dividing 8 (libsodium's blocklist, canonical encodings). The tests decode each one and check
 * 8·P = identity, so a typo here can't hide. */
export const SMALL_ORDER_HEX = Object.freeze([
  '0100000000000000000000000000000000000000000000000000000000000000', // identity (order 1)
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // (0, -1) (order 2)
  '0000000000000000000000000000000000000000000000000000000000000000', // order 4
  '0000000000000000000000000000000000000000000000000000000000000080', // order 4
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', // order 8
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85', // order 8
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', // order 8
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', // order 8
]);

/** RFC 8032 decoding, strict: y < p, a real square root, and no "negative zero" x. Returns [x, y] or null. */
export function decodePoint(b) {
  if (!(b instanceof Uint8Array) || b.length !== 32) return null;
  const sign = BigInt(b[31] >> 7);
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? b[i] & 0x7f : b[i]);
  if (y >= p) return null;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  const x2 = mod(u * inv(v));
  let x = pow(x2, (p + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null;
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = p - x;
  return [x, y];
}

function add([x1, y1], [x2, y2]) {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + y1 * x2) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(mod(1n - t)))];
}

/** 8·P == identity. */
export function isSmallOrder(P) {
  let Q = P;
  for (let i = 0; i < 3; i++) Q = add(Q, Q);
  return Q[0] === 0n && Q[1] === 1n;
}

// ---- the request ----
const HEX = { pk: /^[0-9a-f]{64}$/, sig: /^[0-9a-f]{128}$/, nonce: /^[0-9a-f]{64}$/ };

function validate(o) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new Refused('wire');
  const got = Object.keys(o).sort();
  if (got.length !== KEYS.length || [...KEYS].sort().some((k, i) => k !== got[i])) throw new Refused('wire');
  if (typeof o.op !== 'string' || !Object.hasOwn(AUTH_OPS, o.op)) throw new Refused('wire');
  for (const k of ['pk', 'sig', 'nonce']) if (typeof o[k] !== 'string' || !HEX[k].test(o[k])) throw new Refused('wire');
  try {
    return {
      op: o.op, H_e: parseFieldElement(o.H_e, 'H_e'), N: parseFieldElement(o.N, 'N'), K: parseFieldElement(o.K, 'K'),
      pk: Buffer.from(o.pk, 'hex'), sig: Buffer.from(o.sig, 'hex'), nonce: Buffer.from(o.nonce, 'hex'),
    };
  } catch (e) {
    if (e instanceof WireError) throw new Refused('wire');
    throw e;
  }
}

/** Parse a raw request body strictly. Throws an Error whose message is "wire". */
export function parseAuthRequest(raw) {
  let o;
  try {
    o = JSON.parse(raw);
  } catch {
    throw new Refused('wire');
  }
  return validate(o);
}

let poseidonP = null;
/** @returns {Promise<{ok: true} | {ok: false, reason: 'wire' | 'auth'}>} */
export async function verifyAuth(obj, { poseidon } = {}) {
  let q;
  try {
    q = validate(obj);
  } catch (e) {
    if (e instanceof Refused) return { ok: false, reason: e.reason };
    throw e;
  }
  const P = poseidon ?? await (poseidonP ??= buildPoseidon());
  const A = decodePoint(q.pk);
  const pkOk = A !== null && !isSmallOrder(A);
  let S = 0n;
  for (let i = 63; i >= 32; i--) S = (S << 8n) | BigInt(q.sig[i]);
  const sOk = S < L;
  const kOk = P.F.toObject(P(kInputs(q.pk))) === q.K;
  let sigOk = false;
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: q.pk.toString('base64url') }, format: 'jwk' });
    sigOk = edVerify(null, authMessage(q.op, q.H_e, q.N, q.nonce), key, q.sig);
  } catch {
    sigOk = false;
  }
  return pkOk && sOk && kOk && sigOk ? { ok: true } : { ok: false, reason: 'auth' };
}

async function main() {
  let code = 2;
  let line = { ok: false, reason: 'internal' };
  try {
    if (process.argv.length !== 2) throw new Refused('usage');
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > MAX_STDIN) throw new Refused('wire');
      chunks.push(chunk);
    }
    const res = await verifyAuth(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    line = res;
    code = res.ok === true ? 0 : 1;
  } catch (e) {
    if (e instanceof Refused) {
      line = { ok: false, reason: e.reason };
      code = 1;
    } else if (e instanceof SyntaxError) {
      line = { ok: false, reason: 'wire' };
      code = 1;
    }
  }
  process.stdout.write(JSON.stringify(line) + '\n', () => process.exit(code));
}

// Same entry-point rule as verify.mjs: compare REAL paths, so a symlinked or relative launch still runs main().
function isEntryPoint() {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}
if (isEntryPoint()) main();
