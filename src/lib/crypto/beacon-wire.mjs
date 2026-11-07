// #588 mutual-trust beacon: the ONE wire parser/serializer for deposits, imported by BOTH the prover (client, TS via allowJs)
// and the verifier (plain node, no build step), so there is no second implementation to drift.
//
// A deposit is { proof, publicSignals } and nothing else. The verifier DERIVES slot = H_e, nullifier = N and poll key = K
// from the public signals in the circuit's order [e, H_e, N, K]; a field the wire never carries can't disagree with the proof.
// One spelling per value: canonical decimal (`0` or `[1-9][0-9]*`, ASCII only), so serialize(parse(s)) === s and every
// dedupe key is the parsed bigint, never the wire string. Values are checked against their field order BEFORE anything else
// sees them, so `N` and `N + r` (the same field element in-circuit) can never count as two nullifiers.
// Cheap checks run first: raw size, then string length (<= 77 digits) before any BigInt parse.
// Not checked here (needs the curve): on-curve and the G2 subgroup. The verifier does those before the pairing.

/** Thrown for any input this module refuses. The message names the field, never echoes the value. */
export class WireError extends Error {}

/** BN254 scalar field order (public signals live here). */
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** BN254 base field order (proof point coordinates live here). */
export const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
/** Both orders have 77 decimal digits, so no canonical value is longer. */
export const MAX_DIGITS = 77;
/** Raw deposit body cap, checked before JSON.parse. A canonical deposit is about 1.3 KB. */
export const MAX_DEPOSIT_BYTES = 16 * 1024;
/** The circuit's public signal order (compiled .sym, witness indices 1..4). */
export const SIGNAL_ORDER = Object.freeze(['e', 'H_e', 'N', 'K']);

const CANONICAL = /^(0|[1-9][0-9]*)$/;

/** @param {unknown} s @param {bigint} order @param {string} what @returns {bigint} */
function canon(s, order, what) {
  if (typeof s !== 'string') throw new WireError(`${what}: not a string`);
  if (s.length === 0 || s.length > MAX_DIGITS) throw new WireError(`${what}: bad length`);
  if (!CANONICAL.test(s)) throw new WireError(`${what}: not canonical decimal`);
  const v = BigInt(s);
  if (v >= order) throw new WireError(`${what}: not below the field order`);
  return v;
}

/** @param {unknown} o @param {string[]} keys @param {string} what */
function exactKeys(o, keys, what) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new WireError(`${what}: not an object`);
  const got = Object.keys(o).sort();
  const want = [...keys].sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) throw new WireError(`${what}: wrong keys`);
}

/**
 * Exactly four canonical signals, each < r, in the order [e, H_e, N, K].
 * @param {unknown} arr
 * @returns {{ e: bigint, H_e: bigint, N: bigint, K: bigint }}
 */
export function parseSignals(arr) {
  if (!Array.isArray(arr) || arr.length !== SIGNAL_ORDER.length) throw new WireError('publicSignals: need exactly 4');
  for (const [i, s] of arr.entries()) {                          // every length/shape check before any BigInt
    if (typeof s !== 'string' || s.length === 0 || s.length > MAX_DIGITS) throw new WireError(`publicSignals[${i}]: bad length`);
  }
  const out = {};
  SIGNAL_ORDER.forEach((name, i) => { out[name] = canon(arr[i], R, `publicSignals.${name}`); });
  return /** @type {{ e: bigint, H_e: bigint, N: bigint, K: bigint }} */ (out);
}

/** @param {{ e: bigint, H_e: bigint, N: bigint, K: bigint }} s @returns {string[]} */
export function serializeSignals(s) {
  return SIGNAL_ORDER.map((name) => {
    const v = s[name];
    if (typeof v !== 'bigint' || v < 0n || v >= R) throw new WireError(`${name}: out of range`);
    return v.toString(10);
  });
}

/** @param {unknown} pt @param {string} what @returns {[bigint, bigint]} */
function g1(pt, what) {
  if (!Array.isArray(pt) || pt.length !== 3) throw new WireError(`${what}: need [x, y, "1"]`);
  if (pt[2] !== '1') throw new WireError(`${what}: affine only (z must be "1")`);
  const x = canon(pt[0], Q, `${what}.x`);
  const y = canon(pt[1], Q, `${what}.y`);
  if (x === 0n && y === 0n) throw new WireError(`${what}: identity`);
  return [x, y];
}

/** @param {unknown} pt @param {string} what @returns {[[bigint, bigint], [bigint, bigint]]} */
function g2(pt, what) {
  if (!Array.isArray(pt) || pt.length !== 3) throw new WireError(`${what}: need [x, y, ["1","0"]]`);
  const [x, y, z] = pt;
  if (!Array.isArray(z) || z.length !== 2 || z[0] !== '1' || z[1] !== '0') throw new WireError(`${what}: affine only`);
  for (const c of [x, y]) if (!Array.isArray(c) || c.length !== 2) throw new WireError(`${what}: coordinate shape`);
  const X = [canon(x[0], Q, `${what}.x0`), canon(x[1], Q, `${what}.x1`)];
  const Y = [canon(y[0], Q, `${what}.y0`), canon(y[1], Q, `${what}.y1`)];
  if (X[0] === 0n && X[1] === 0n && Y[0] === 0n && Y[1] === 0n) throw new WireError(`${what}: identity`);
  return [X, Y];
}

/**
 * A groth16/bn128 proof in snarkjs's JSON shape, affine points only, every coordinate canonical and < q.
 * @param {unknown} p
 */
export function parseProof(p) {
  exactKeys(p, ['protocol', 'curve', 'pi_a', 'pi_b', 'pi_c'], 'proof');
  const o = /** @type {Record<string, unknown>} */ (p);
  if (o.protocol !== 'groth16') throw new WireError('proof.protocol: groth16 only');
  if (o.curve !== 'bn128') throw new WireError('proof.curve: bn128 only');
  return { pi_a: g1(o.pi_a, 'pi_a'), pi_b: g2(o.pi_b, 'pi_b'), pi_c: g1(o.pi_c, 'pi_c') };
}

/**
 * Parse a raw deposit body. Only { proof, publicSignals }; any other key (slot, N, K, payload, ...) is refused.
 * @param {string} raw
 */
export function parseDeposit(raw) {
  if (typeof raw !== 'string') throw new WireError('deposit: not a string');
  if (raw.length > MAX_DEPOSIT_BYTES) throw new WireError('deposit: too large');
  let obj;
  try {
    obj = JSON.parse(raw);
  } catch {
    throw new WireError('deposit: not JSON');
  }
  exactKeys(obj, ['proof', 'publicSignals'], 'deposit');
  return { proof: parseProof(obj.proof), signals: parseSignals(obj.publicSignals) };
}
