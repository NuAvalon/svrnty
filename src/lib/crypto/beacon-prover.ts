// src/lib/crypto/beacon-prover.ts
// #588 trust beacon, PROVER half (client). Dark: nothing imports this module yet.
// Rules (task:588 rulings): the deposit is { proof, publicSignals } built ONLY by beacon-wire.mjs's serializeDeposit; DS_K, the public-key split
// and the signed message come ONLY from beacon-wire.mjs (one implementation); the epoch and grace constants are IMPORTED from it, never defined
// here; snarkjs and circomlibjs are loaded ONLY by a dynamic import() on the flagged trust path, never statically; every random byte comes from
// the platform CSPRNG (never Math.random); every refusal is a ProverRefused with a fixed reason code and a fixed message (no secret value in it).
/* eslint-disable @typescript-eslint/no-explicit-any */
import * as wire from './beacon-wire.mjs';

export type Point = readonly [bigint, bigint];

export interface DepositKeys {
  /** This party's beacon secret scalar, 1 <= x < the babyjub subgroup order. */
  x: bigint;
  /** The counterpart's beacon public key. MUST come from the verified contact record (T4 signed-card key: not built in this tree yet). */
  counterpartY: Point;
  /** The epoch: floor(unix_seconds / EPOCH_SECONDS). */
  epoch: bigint;
  /** The 32 bytes of this deposit's one-time Ed25519 public key; K = Poseidon(DS_K, lo, hi) by beacon-wire.mjs's split. */
  oneTimePk: Uint8Array;
}

export interface Signals { e: bigint; H_e: bigint; N: bigint; K: bigint }

interface DerivedDeposit {
  /** The circuit's witness input, every value a canonical decimal string. INTERNAL: it contains x. */
  input: Record<string, string>;
  /** What the proof's publicSignals will be, in the pinned order [e, H_e, N, K]. */
  signals: Signals;
}

/** Every deliberate refusal throws this, with one of a fixed set of reason codes (the tests assert the REASON). Reasons: y-identity, y-off-curve,
 * y-small-order, y-not-in-subgroup, y-self, x-range, epoch-range, pk-length, epoch-too-short, rand-range, op, nonce, signals-mismatch.
 * Messages are fixed strings: they never contain a secret value. The refusal happens UP FRONT, never inside witness generation. */
export class ProverRefused extends Error {
  constructor(public readonly reason: string) { super(`refused: ${reason}`); this.name = 'ProverRefused'; }
}

const big = (s: string) => BigInt(s);
/** The BN254 scalar field order r (a public constant of the curve), and the Baby Jubjub prime-subgroup order L (public). */
const R = big('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const L = big('2736030358979909402780800718157159386076813972158567259200215660948447373041');
const EIGHT = big('8');

const modPow = (b: bigint, e: bigint, m: bigint): bigint => {
  let r = big('1'); b %= m;
  for (; e > big('0'); e >>= big('1')) { if (e & big('1')) r = (r * b) % m; b = (b * b) % m; }
  return r;
};
/** 8^-1 mod L (L is prime): the prover-side cofactor witness is Q = (8^-1 mod L) * Y, so that 8*Q = Y with Q in the prime-order subgroup. */
const INV8 = modPow(EIGHT, L - big('2'), L);

// ---- lazy libraries: literal dynamic imports so the bundler can split them into a chunk that only the trust path loads ----
let libs: Promise<{ bj: any; poseidon: any }> | null = null;
const loadCurve = () => (libs ??= import('circomlibjs').then(async (m: any) => ({ bj: await m.buildBabyjub(), poseidon: await m.buildPoseidon() })));

// ---- randomness: the platform CSPRNG only ----
/** Random bytes from the platform CSPRNG (crypto.getRandomValues). The ONLY default randomness source in the beacon modules. */
export function defaultRandomBytes(n: number): Uint8Array {
  const c: Crypto | undefined = (globalThis as any).crypto;
  if (!c || typeof c.getRandomValues !== 'function') throw new Error('no CSPRNG available');
  return c.getRandomValues(new Uint8Array(n));
}

/** A FRESH one-time Ed25519 key per deposit: a seed from the CSPRNG and its public key (the 32 bytes whose Poseidon split is K).
 * `random` is a test seam; its default is defaultRandomBytes. The seed is returned to the caller only and never serialized. */
export async function newOneTimeKey(random: (n: number) => Uint8Array = defaultRandomBytes): Promise<{ seed: Uint8Array; pk: Uint8Array }> {
  const seed = random(32);
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new ProverRefused('pk-length');
  const pkcs8 = new Uint8Array(48);
  pkcs8.set([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20], 0);
  pkcs8.set(seed, 16);
  const key = await (globalThis as any).crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await (globalThis as any).crypto.subtle.exportKey('jwk', key);
  const b64 = String(jwk.x).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const pk = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  if (pk.length !== 32) throw new ProverRefused('pk-length');
  return { seed: new Uint8Array(seed), pk };
}

/** The absolute time (ms) to re-deposit inside an epoch: uniform over [start + grace, end - grace], never at a boundary. `rand` is injected
 * (default: the CSPRNG). epochSeconds / graceSeconds DEFAULT to the constants in beacon-wire.mjs, the ONE place they are defined. */
export function scheduleRedeposit(o: { epochStartMs: number; epochSeconds?: number; graceSeconds?: number; rand?: () => number }): number {
  const epochSeconds = o.epochSeconds ?? (wire as any).EPOCH_SECONDS, graceSeconds = o.graceSeconds ?? (wire as any).GRACE_SECONDS;
  if (typeof epochSeconds !== 'number' || typeof graceSeconds !== 'number') throw new ProverRefused('epoch-too-short');
  if (!(epochSeconds > 2 * graceSeconds)) throw new ProverRefused('epoch-too-short');
  const rand = o.rand ?? (() => new DataView(defaultRandomBytes(4).buffer).getUint32(0) / 2 ** 32);
  const r = rand();
  if (!(typeof r === 'number' && r >= 0 && r < 1)) throw new ProverRefused('rand-range');
  return o.epochStartMs + graceSeconds * 1000 + Math.floor(r * (epochSeconds - 2 * graceSeconds) * 1000);
}

const isId = (bj: any, p: any) => bj.F.toObject(p[0]) === big('0') && bj.F.toObject(p[1]) === big('1');

/** The public signals [e, H_e, N, K] ONLY. This is the only exported derivation: the witness (which holds the beacon secret x) never leaves this
 * module, so no caller can log or store it by accident. Same refusals as the witness builder, up front. */
export async function deriveSignals(k: DepositKeys): Promise<Signals> {
  return (await deriveWitness(k)).signals;
}

/** INTERNAL (not exported): derive the circuit input and the expected public signals. Refuses, with a reason code and BEFORE any proving file is
 * touched: an out-of-range x or epoch, a one-time key that is not 32 bytes, and a counterpart key that is the identity, off the curve, of small
 * order, not in the prime-order subgroup, or equal to our own. */
async function deriveWitness(k: DepositKeys): Promise<DerivedDeposit> {
  // pure range checks first: they need no curve library
  if (typeof k.x !== 'bigint' || k.x < big('1') || k.x >= L) throw new ProverRefused('x-range');
  if (typeof k.epoch !== 'bigint' || k.epoch < big('0') || k.epoch >= R) throw new ProverRefused('epoch-range');
  if (!(k.oneTimePk instanceof Uint8Array) || k.oneTimePk.length !== 32) throw new ProverRefused('pk-length');
  const [Yx, Yy] = k.counterpartY;
  if (typeof Yx !== 'bigint' || typeof Yy !== 'bigint' || Yx < big('0') || Yy < big('0') || Yx >= R || Yy >= R) throw new ProverRefused('y-off-curve');

  const { bj, poseidon } = await loadCurve();
  const F = bj.F, O = (e: any) => F.toObject(e) as bigint, P_ = (v: bigint) => F.e(v);
  const Y = [P_(Yx), P_(Yy)];
  if (Yx === big('0') && Yy === big('1')) throw new ProverRefused('y-identity');
  if (!bj.inCurve(Y)) throw new ProverRefused('y-off-curve');
  if (isId(bj, bj.mulPointEscalar(Y, EIGHT))) throw new ProverRefused('y-small-order');            // order 1, 2, 4 or 8
  if (!isId(bj, bj.mulPointEscalar(Y, L))) throw new ProverRefused('y-not-in-subgroup');             // a torsion component is present
  const P = bj.mulPointEscalar(bj.Base8, k.x);
  if (O(P[0]) === Yx && O(P[1]) === Yy) throw new ProverRefused('y-self');

  const S = bj.mulPointEscalar(Y, k.x);
  const Q = bj.mulPointEscalar(Y, INV8);                                                              // 8 * Q = Y, Q in the prime-order subgroup
  const q8 = bj.mulPointEscalar(Q, EIGHT);
  if (O(q8[0]) !== Yx || O(q8[1]) !== Yy) throw new ProverRefused('y-not-in-subgroup');
  const px = O(P[0]), py = O(P[1]);
  const pFirst = px < Yx || (px === Yx && py < Yy);                                                   // FULL-WIDTH lexicographic order (x, then y)
  const [minx, miny, maxx, maxy] = pFirst ? [px, py, Yx, Yy] : [Yx, Yy, px, py];
  const w = wire as any;
  const H = O(poseidon([w.asciiTag('svrnty:588:slot:v1'), O(S[0]), O(S[1]), minx, miny, maxx, maxy, k.epoch]));
  const N = O(poseidon([w.asciiTag('svrnty:588:null:v1'), k.x, H]));
  const K = O(poseidon(w.kInputs(k.oneTimePk)));
  const signals: Signals = { e: k.epoch, H_e: H, N, K };
  const input: Record<string, string> = {
    e: String(k.epoch), H_e: String(H), N: String(N), K: String(K), x: String(k.x),
    Yx: String(Yx), Yy: String(Yy), Qx: String(O(Q[0])), Qy: String(O(Q[1])),
  };
  return { input, signals };
}

/** Prove and serialize: groth16.fullProve on in-memory wasm + zkey (read ONLY after the inputs were accepted), check the proof's signals equal
 * the derived ones, then beacon-wire.mjs's serializeDeposit. Nothing else is ever placed in the body. */
export async function buildDeposit(k: DepositKeys, files: { wasm: Uint8Array; zkey: Uint8Array }): Promise<string> {
  const d = await deriveWitness(k);                                  // refuses here, before the files are touched
  const snarkjs: any = await import('snarkjs');
  let proof: unknown, publicSignals: unknown;
  try {
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(d.input, { type: 'mem', data: files.wasm }, { type: 'mem', data: files.zkey }));
  } finally {
    // snarkjs keeps a multi-threaded curve (worker threads) in a global; release it so no worker outlives the proof. The next proof rebuilds it.
    const c = (globalThis as any).curve_bn128;
    if (c && typeof c.terminate === 'function') { try { await c.terminate(); } catch { /* already gone */ } delete (globalThis as any).curve_bn128; }
  }
  const want = [d.signals.e, d.signals.H_e, d.signals.N, d.signals.K].map(String);
  if (!Array.isArray(publicSignals) || publicSignals.length !== 4 || publicSignals.some((s: unknown, i: number) => s !== want[i])) throw new ProverRefused('signals-mismatch');
  const w = wire as any;
  return w.serializeDeposit({ proof: w.parseProof(proof), signals: d.signals });
}

/** Sign a poll / withdraw: calls `sign` with exactly authMessage(op, H_e, N, nonce) from beacon-wire.mjs, nothing else. A bad op or nonce is
 * refused BEFORE anything is signed. */
export async function signAuth(op: 'poll' | 'withdraw', H_e: bigint, N: bigint, nonce: Uint8Array, sign: (msg: Uint8Array) => Promise<Uint8Array>): Promise<Uint8Array> {
  const w = wire as any;
  if (typeof op !== 'string' || !Object.hasOwn(w.AUTH_OPS, op)) throw new ProverRefused('op');
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32) throw new ProverRefused('nonce');
  return sign(w.authMessage(op, H_e, N, nonce));
}
