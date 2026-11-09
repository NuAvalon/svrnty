// src/lib/crypto/beacon-key.ts
// #588 T4, first piece: the beacon KEY. Generation (fresh random, never derived: Flint's 10-31 ruling), the canonical 32-byte base64 encoding that
// rides the signed card as identity.beacon_public_key, and the receiver's checks on a key that arrives on a card (T4 note v0.2 §3).
// DARK: nothing imports this. circomlibjs is loaded ONLY by a dynamic import() on the (flagged) trust path, like the prover.

export const BEACON_KEY_BYTES = 32;

// THE ENCODING (pinned here and in the card spec; a Weft client must produce identical bytes): 32 bytes. y is the point's affine y as a
// 255-bit little-endian integer, REQUIRED < p. Bit 7 of byte 31 is 1 exactly when x > (p-1)/2, else 0. The decoder recovers x from the curve
// equation a*x^2 + y^2 = 1 + d*x^2*y^2 (a = 168700, d = 168696), picks the root whose side of (p-1)/2 matches the bit, and refuses a 1 bit on x = 0.
// This is NOT circomlibjs.packPoint: that function was measured to set the sign bit differently for a point it just computed than for the
// same point after unpackPoint, so it cannot define a canonical form.

/** Order of the BabyJubJub prime-order subgroup (the same constant the circuit and the prover use). */
const L = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');
/** Exported for the identity-key record's strict range check (1 <= x < l). */
export const BEACON_ORDER = L;
const ZERO = BigInt(0), ONE = BigInt(1), EIGHT = BigInt(8);
const FIELD_P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const HALF = (FIELD_P - ONE) / BigInt(2);
const CURVE_A = BigInt(168700), CURVE_D = BigInt(168696);

// 'unavailable' = the check could not run (the curve library failed to load, or a curve operation threw): NOT a verdict on the key, so it is not 'encoding'.
export type BeaconKeyReason = 'encoding' | 'off-curve' | 'identity' | 'small-order' | 'not-in-subgroup' | 'own-key' | 'unavailable';
export type BeaconKeyCheck = { ok: true; point: readonly [bigint, bigint] } | { ok: false; reason: BeaconKeyReason };

/** Caches a SUCCESSFUL load and forgets a failed one: with `??=` alone a single failed import() stayed cached and failed every later check. */
export function makeCurveLoader(load: () => Promise<any>): () => Promise<any> {
  let cached: Promise<any> | undefined;
  return () => {
    if (!cached) {
      const p = Promise.resolve().then(load);
      cached = p;
      p.catch(() => { if (cached === p) cached = undefined; });
    }
    return cached;
  };
}
const loadCurve = makeCurveLoader(() => import('circomlibjs').then((m: any) => m.buildBabyjub()));

function defaultRandomBytes(n: number): Uint8Array {
  const c: Crypto | undefined = (globalThis as any).crypto;
  if (!c || typeof c.getRandomValues !== 'function') throw new Error('no CSPRNG available');
  return c.getRandomValues(new Uint8Array(n));
}

/** A fresh beacon secret x, uniform in [1, L): 251 random bits, REJECTED (never reduced) when 0 or >= L, so there is no modular bias.
 * `random` is a test seam. The secret is returned to the caller only: this module never stores or logs it. */
export async function generateBeaconSecret(random: (n: number) => Uint8Array = defaultRandomBytes): Promise<bigint> {
  for (let i = 0; i < 256; i++) {
    const b = random(32);
    if (!(b instanceof Uint8Array) || b.length !== 32) throw new Error('bad random source');
    const m = new Uint8Array(b);
    m[31] &= 0x07; // 251 bits: L is a 251-bit number
    let x = ZERO;
    for (let j = 31; j >= 0; j--) x = (x << EIGHT) | BigInt(m[j]); // little-endian
    if (x >= ONE && x < L) return x;
  }
  throw new Error('random source produced no usable secret');
}

const toB64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));

/** The public key for secret x: base64 of the 32-byte canonical compressed BabyJubJub point x*Base8. */
export async function beaconPublicKey(x: bigint): Promise<string> {
  if (typeof x !== 'bigint' || x < ONE || x >= L) throw new RangeError('beacon secret out of range');
  const bj = await loadCurve();
  const P = bj.mulPointEscalar(bj.Base8, x);
  return toB64(packCanonical(bj.F.toObject(P[0]), bj.F.toObject(P[1])));
}

/** The pinned encoding (see the header). Input are canonical field integers. */
function packCanonical(x: bigint, y: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = y;
  for (let i = 0; i < 32; i++) { out[i] = Number(v & BigInt(0xff)); v >>= EIGHT; }
  if (x > HALF) out[31] |= 0x80;
  return out;
}

/** Strict base64 of exactly 32 bytes: 44 characters, canonical (re-encoding gives the same string), nothing else. */
function decode32(s: unknown): Uint8Array | null {
  if (typeof s !== 'string' || s.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/.test(s)) return null;
  let bin: string;
  try { bin = atob(s); } catch { return null; }
  if (bin.length !== BEACON_KEY_BYTES) return null;
  const u = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  return toB64(u) === s ? u : null;
}

/** The receiver's checks, in the ruled order: canonical decode, on the curve, not the identity, not of small order, in the prime-order
 * subgroup (l*Y = O), not my own key. NEVER throws and returns a fixed reason word, never the input. A failure drops the KEY only (the card is kept). */
export async function checkBeaconPublicKey(b64: unknown, ownPublicKey?: string, loader: () => Promise<any> = loadCurve): Promise<BeaconKeyCheck> {
  const bytes = decode32(b64);
  if (!bytes) return { ok: false, reason: 'encoding' };
  try {
    return checkOnCurve(await loader(), bytes, b64 as string, ownPublicKey);
  } catch {
    return { ok: false, reason: 'unavailable' }; // a fixed word: the thrown error (which could carry anything) is dropped
  }
}

function checkOnCurve(bj: any, bytes: Uint8Array, b64: string, ownPublicKey?: string): BeaconKeyCheck {
  const sign = (bytes[31] & 0x80) !== 0;
  let y = ZERO;
  for (let j = 31; j >= 0; j--) y = (y << EIGHT) | BigInt(j === 31 ? bytes[j] & 0x7f : bytes[j]);
  if (y >= FIELD_P) return { ok: false, reason: 'encoding' }; // an alias of y - p
  const F = bj.F;
  const y2 = F.square(F.e(y));
  const den = F.sub(F.e(CURVE_A), F.mul(F.e(CURVE_D), y2));
  if (F.isZero(den)) return { ok: false, reason: 'off-curve' };
  const x2 = F.div(F.sub(F.one, y2), den);
  // F.sqrt is a wasm Tonelli-Shanks that NEVER RETURNS on a non-residue (measured: it hangs), so a hostile card could freeze the receiver.
  // Ask isSquare first; it is the reason this check exists in this order.
  if (!F.isSquare(x2)) return { ok: false, reason: 'off-curve' };
  let xe = F.sqrt(x2);
  if (xe === null || xe === undefined) return { ok: false, reason: 'off-curve' };
  const xo = F.toObject(xe) as bigint;
  if (xo === ZERO && sign) return { ok: false, reason: 'encoding' }; // x = 0 has no negative side
  if ((xo > HALF) !== sign) xe = F.neg(xe);
  const pt = [xe, F.e(y)];
  if (!bj.inCurve(pt)) return { ok: false, reason: 'off-curve' };
  const O = (e: any) => bj.F.toObject(e) as bigint;
  const isId = (p: any) => O(p[0]) === ZERO && O(p[1]) === ONE;
  if (isId(pt)) return { ok: false, reason: 'identity' };
  if (isId(bj.mulPointEscalar(pt, EIGHT))) return { ok: false, reason: 'small-order' };
  if (!isId(bj.mulPointEscalar(pt, L))) return { ok: false, reason: 'not-in-subgroup' };
  if (typeof ownPublicKey === 'string' && ownPublicKey === b64) return { ok: false, reason: 'own-key' };
  return { ok: true, point: [O(pt[0]), O(pt[1])] as const };
}
