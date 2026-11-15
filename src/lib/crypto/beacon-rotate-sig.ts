/* eslint-disable @typescript-eslint/no-explicit-any -- the curve object comes from circomlibjs, which ships no types */
// src/lib/crypto/beacon-rotate-sig.ts: the beacon key under rotation. The OLD-BEACON-KEY proof inside a `beacon.rotate`: a Schnorr signature over Baby Jubjub
// with the old beacon secret x_old, over the WHOLE statement, so it cannot be replayed onto another rotation. DARK: nothing imports this yet.
//
//   M   = beaconFrame(tag 'svrnty:beacon-rotate:v1', durable_id, identity fingerprint, old pk, old gen, new pk, new gen)   (the identity signature signs the SAME M)
//   k   = SHA-512(frame(nonce tag, x_old 32 B LE) || M)   read as a 512-bit LITTLE-endian integer, mod l     (deterministic: no RNG failure can reuse a nonce)
//   R   = k * Base8                                       32 B card form
//   e   = SHA-512(frame(chal tag, R) || M)                 same reading, mod l
//   s   = (k + e * x_old) mod l                            32 B little-endian
//   sig = R || s                                           64 B
//   verify: R and the old key pass the card checks, s < l (no malleable s + l), s*Base8 == R + e*X_old
//
// The generation ORDER (new > old) is NOT checked here: it is the RECEIVER's rule (R2 of the gate-15 design), which also needs the held generation.
// This module only proves possession of x_old over a well-formed statement.
import { ProverRefused } from './beacon-prover';
import { beaconFrame, asciiField, hexField, keyField, u32Field } from './beacon-frame';
import { BEACON_ORDER, beaconPublicKey, checkBeaconPublicKey, decodeBeaconKey, loadCurve } from './beacon-key';

export const ROTATE_TAG = 'svrnty:beacon-rotate:v1';
const NONCE_TAG = 'svrnty:beacon-rotate:nonce:v1';
const CHAL_TAG = 'svrnty:beacon-rotate:chal:v1';

export type RotateStatement = {
  /** 64 lowercase hex characters. */
  durableId: string;
  /** The identity fingerprint, 64 lowercase hex characters. */
  identityFingerprint: string;
  /** The old and the new beacon public keys, card form, base64. */
  oldPk: string;
  oldGen: number;
  newPk: string;
  newGen: number;
};

export type RotateReason = 'sig-length' | 'statement' | 's-range' | 'r-encoding' | 'r-off-curve' | 'r-small-order' | 'r-not-in-subgroup' | 'old-key' | 'unavailable' | 'mismatch';
export type RotateVerdict = { ok: true } | { ok: false; reason: RotateReason };

const ZERO = BigInt(0), EIGHT = BigInt(8), BYTE = BigInt(255);

const leInt = (b: Uint8Array): bigint => {
  let v = ZERO;
  for (let i = b.length - 1; i >= 0; i--) v = (v << EIGHT) | BigInt(b[i]);
  return v;
};
const le32 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let t = v;
  for (let i = 0; i < 32; i++) { out[i] = Number(t & BYTE); t >>= EIGHT; }
  return out;
};
const sha512 = async (...parts: Uint8Array[]): Promise<Uint8Array> => {
  const cat = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { cat.set(p, off); off += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-512', cat));
};
const toB64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));

/** M. Refuses with ProverRefused('statement') for any malformed field (non-canonical hex, a key that is not strict card-form base64, a generation out of
 * range). Pure: no curve library. */
export function rotateMessage(s: RotateStatement): Uint8Array {
  return beaconFrame([
    asciiField(ROTATE_TAG), hexField(s.durableId), hexField(s.identityFingerprint),
    keyField(s.oldPk), u32Field(s.oldGen), keyField(s.newPk), u32Field(s.newGen),
  ]);
}

const challenge = async (R: Uint8Array, M: Uint8Array): Promise<bigint> => leInt(await sha512(beaconFrame([asciiField(CHAL_TAG), R]), M)) % BEACON_ORDER;

/** Sign the statement with the OLD beacon secret. Refuses (ProverRefused): 'statement' for a malformed field; 'x-range' for a secret outside [1, l);
 * 'old-key' when x_old * Base8 is not `oldPk` (a client never signs for a key it does not hold); 'nonce' when the derived k is 0 (~2^-251: refuse, never retry). */
export async function signRotate(xOld: bigint, s: RotateStatement): Promise<Uint8Array> {
  const M = rotateMessage(s);
  if (typeof xOld !== 'bigint' || xOld < BigInt(1) || xOld >= BEACON_ORDER) throw new ProverRefused('x-range');
  if ((await beaconPublicKey(xOld)) !== s.oldPk) throw new ProverRefused('old-key');
  const k = leInt(await sha512(beaconFrame([asciiField(NONCE_TAG), le32(xOld)]), M)) % BEACON_ORDER;
  if (k === ZERO) throw new ProverRefused('nonce');
  const R = decodeBeaconKey(await beaconPublicKey(k));
  if (R === null) throw new ProverRefused('statement');
  const e = await challenge(R, M);
  const sig = new Uint8Array(64);
  sig.set(R, 0);
  sig.set(le32((k + e * xOld) % BEACON_ORDER), 32);
  return sig;
}

const R_REASON: Record<string, RotateReason> = {
  encoding: 'r-encoding', 'off-curve': 'r-off-curve', identity: 'r-small-order', 'small-order': 'r-small-order',
  'not-in-subgroup': 'r-not-in-subgroup', 'own-key': 'r-encoding', unavailable: 'unavailable',
};

/** Verify. Never throws; the verdict carries a fixed reason. Order: signature length, the statement (BEFORE any curve math), s < l, R (card checks), the
 * old key (card checks), then the equation. A signature moved onto another statement fails as 'mismatch'. */
export async function verifyRotate(s: RotateStatement, sig: Uint8Array): Promise<RotateVerdict> {
  if (!(sig instanceof Uint8Array) || sig.length !== 64) return { ok: false, reason: 'sig-length' };
  let M: Uint8Array;
  try { M = rotateMessage(s); } catch { return { ok: false, reason: 'statement' }; }
  const Rb = sig.slice(0, 32);
  const sv = leInt(sig.slice(32));
  if (sv >= BEACON_ORDER) return { ok: false, reason: 's-range' };
  const R = await checkBeaconPublicKey(toB64(Rb));
  if (!R.ok) return { ok: false, reason: R_REASON[R.reason] ?? 'r-encoding' };
  const X = await checkBeaconPublicKey(s.oldPk);
  if (!X.ok) return { ok: false, reason: X.reason === 'unavailable' ? 'unavailable' : 'old-key' };
  try {
    const bj: any = await loadCurve();
    const F = bj.F;
    const pt = (p: readonly [bigint, bigint]) => [F.e(p[0]), F.e(p[1])];
    const e = await challenge(Rb, M);
    const lhs = bj.mulPointEscalar(bj.Base8, sv);
    const rhs = bj.addPoint(pt(R.point), bj.mulPointEscalar(pt(X.point), e));
    return F.eq(lhs[0], rhs[0]) && F.eq(lhs[1], rhs[1]) ? { ok: true } : { ok: false, reason: 'mismatch' };
  } catch {
    return { ok: false, reason: 'unavailable' };
  }
}
