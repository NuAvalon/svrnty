// src/lib/crypto/beacon-slotbind-matcher.ts
// #588: the satellite-side MODEL of the slot-binding matcher (in memory; the real service is not built). It does the three things that make the proof
// mean something, in this order: (1) refuse any non-canonical public input BEFORE verification (R1), (2) verify the proof against the canonical values,
// (3) dedupe nullifiers on the CANONICAL value per slot and fire a match only on TWO DISTINCT nullifiers. The verifier is injected, because the production
// one is not chosen (Groth16 in Python is unmeasured). This module does not weaken or replace the beacon v2 crypto files; nothing imports it yet.

import { encodeCanonical, parsePublicInputs, type PublicInputs, type WirePublicInputs } from './beacon-public-inputs';

export interface SlotBindDeposit {
  proof: unknown;
  publicInputs: WirePublicInputs;
}

/** True iff the proof verifies for exactly these canonical public inputs. May be sync or async; a throw counts as false. */
export type VerifyProof = (proof: unknown, publicInputs: PublicInputs) => boolean | Promise<boolean>;

export type DepositResult =
  | { status: 'rejected'; reason: 'malformed-public-inputs' | 'proof-invalid' | 'slot-full' }
  | { status: 'deposited' }
  | { status: 'already-deposited' }
  | { status: 'match'; nullifiers: [string, string]; ks: [string, string] };

interface SlotState {
  /** canonical N (hex) -> canonical K (hex), in arrival order */
  entries: Map<string, string>;
}

export class SlotBindMatcher {
  private readonly slots = new Map<string, SlotState>();

  constructor(private readonly verify: VerifyProof) {}

  async deposit(d: SlotBindDeposit): Promise<DepositResult> {
    // (1) R1: ONE canonical spelling, checked before any verification work (an open mailbox must not buy CPU with garbage).
    const pub = parsePublicInputs(d?.publicInputs);
    if (!pub) return { status: 'rejected', reason: 'malformed-public-inputs' };
    // (2) the proof must verify for exactly these canonical values.
    let ok = false;
    try {
      ok = (await this.verify(d.proof, pub)) === true;
    } catch {
      ok = false;
    }
    if (!ok) return { status: 'rejected', reason: 'proof-invalid' };
    // (3) dedupe and match on the CANONICAL value, per slot.
    const slotKey = encodeCanonical(pub.H_e);
    const n = encodeCanonical(pub.N);
    const k = encodeCanonical(pub.K);
    const slot = this.slots.get(slotKey) ?? { entries: new Map<string, string>() };
    this.slots.set(slotKey, slot);
    if (slot.entries.has(n)) return { status: 'already-deposited' };
    if (slot.entries.size >= 2) return { status: 'rejected', reason: 'slot-full' };
    slot.entries.set(n, k);
    if (slot.entries.size === 2) {
      const [[n1, k1], [n2, k2]] = [...slot.entries.entries()];
      return { status: 'match', nullifiers: [n1, n2], ks: [k1, k2] };
    }
    return { status: 'deposited' };
  }
}
