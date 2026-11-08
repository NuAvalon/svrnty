// src/lib/crypto/beacon-prover.ts
// #588 trust beacon, PROVER half (client). STUB: every function throws until the implementation commit (tests first, red).
// Rules this module must keep (task:588 rulings): the deposit is { proof, publicSignals } built ONLY by beacon-wire.mjs's serializeDeposit;
// DS_K / the public-key split / the signed message come ONLY from beacon-wire.mjs (one implementation); snarkjs and circomlibjs are loaded
// ONLY by a dynamic import on the flagged trust path, never statically.

export type Point = readonly [bigint, bigint];

export interface DepositKeys {
  /** This party's beacon secret scalar, 1 <= x < the babyjub subgroup order. */
  x: bigint;
  /** The counterpart's beacon public key. MUST come from the verified contact record (T4, not built in this tree yet). */
  counterpartY: Point;
  /** The epoch: floor(unix_seconds / 604800). */
  epoch: bigint;
  /** The 32 bytes of this deposit's one-time Ed25519 public key; K = Poseidon(DS_K, lo, hi). */
  oneTimePk: Uint8Array;
}

export interface Signals { e: bigint; H_e: bigint; N: bigint; K: bigint }

export interface DerivedDeposit {
  /** The circuit's witness input, every value a canonical decimal string. */
  input: Record<string, string>;
  /** What the proof's publicSignals will be, in the pinned order [e, H_e, N, K]. */
  signals: Signals;
}

/** Every deliberate refusal throws this, with one of a fixed set of reason codes (the tests assert the REASON, so a stub that throws
 * for any other cause cannot satisfy a refusal test). Reasons: y-identity, y-off-curve, y-small-order, x-range, epoch-range, pk-length,
 * epoch-too-short, rand-range, op, nonce, signals-mismatch. */
export class ProverRefused extends Error {
  constructor(public readonly reason: string) { super(`refused: ${reason}`); this.name = 'ProverRefused'; }
}

const todo = (what: string): never => { throw new Error(`beacon-prover.${what}: not implemented (tests first)`); };

/** Derive the circuit input and the expected public signals. Refuses a counterpart key that is the identity, off the curve, or not in the
 * prime-order subgroup, and an out-of-range x or epoch. */
export async function deriveDeposit(_k: DepositKeys): Promise<DerivedDeposit> { return todo('deriveDeposit'); }

/** Prove and serialize: groth16.fullProve on in-memory wasm + zkey, check the proof's signals equal the derived ones, then serializeDeposit. */
export async function buildDeposit(_k: DepositKeys, _files: { wasm: Uint8Array; zkey: Uint8Array }): Promise<string> { return todo('buildDeposit'); }

/** The absolute time (ms) to re-deposit inside an epoch: uniform over [start + grace, end - grace], never at a boundary. `rand` is injected. */
export function scheduleRedeposit(_o: { epochStartMs: number; epochSeconds: number; graceSeconds: number; rand: () => number }): number { return todo('scheduleRedeposit'); }

/** Sign a poll / withdraw: calls `sign` with exactly authMessage(op, H_e, N, nonce) from beacon-wire.mjs, nothing else. */
export async function signAuth(_op: 'poll' | 'withdraw', _H_e: bigint, _N: bigint, _nonce: Uint8Array, _sign: (msg: Uint8Array) => Promise<Uint8Array>): Promise<Uint8Array> { return todo('signAuth'); }
