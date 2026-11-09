// src/lib/crypto/beacon-redeposit-plan.ts
// #588 piece D, the PURE planning half (DARK; nothing imports it): when is each pending trust's weekly deposit due?
// The jitter inside the epoch comes from HMAC(device secret, trust id, epoch), so a reload or a second plan agrees with the first (no re-roll, no restart
// burst), a different device or epoch gets a different time, and nothing but this device's secret decides it. The time itself is scheduleRedeposit's
// (prover): uniform over [epoch start + grace, epoch end - grace], never at a boundary. No I/O here: the caller stores `done` and does the proving.
import { scheduleRedeposit } from './beacon-prover';
import * as wire from './beacon-wire.mjs';

const TAG = 'svrnty:588:redeposit:v1';

export interface PlanInput {
  nowMs: number;
  /** Ids of the pending trusts (any stable local id; never sent anywhere). */
  trusts: string[];
  /** depositKey(trustId, epoch) for deposits already made. */
  done: ReadonlySet<string>;
  /** 32 bytes, secret, IDENTITY state (one per identity, carried in the backup; not minted per device): the only source of the jitter. */
  seed: Uint8Array;
}
export interface DueDeposit { trustId: string; epoch: number; dueAtMs: number }
export interface Plan {
  /** Jobs whose time has come (including a late catch-up inside the same epoch). */
  due: DueDeposit[];
  /** When to plan again: the earliest FUTURE due time this epoch, else the start of the next epoch (null when there are no trusts). */
  nextAtMs: number | null;
}

export const depositKey = (trustId: string, epoch: number) => `${trustId}:${epoch}`;
export const currentEpoch = (nowMs: number) => Math.floor(nowMs / 1000 / (wire as any).EPOCH_SECONDS);

async function fraction(seed: Uint8Array, trustId: string, epoch: number): Promise<number> {
  const subtle: SubtleCrypto | undefined = (globalThis as any).crypto?.subtle;
  if (!subtle) throw new Error('no WebCrypto available');
  const key = await subtle.importKey('raw', seed, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await subtle.sign('HMAC', key, new TextEncoder().encode(`${TAG}|${epoch}|${trustId}`)));
  return new DataView(mac.buffer).getUint32(0) / 2 ** 32;
}

export async function planDeposits(i: PlanInput): Promise<Plan> {
  if (!(i.seed instanceof Uint8Array) || i.seed.length !== 32) throw new Error('planDeposits: seed must be 32 bytes');
  if (typeof i.nowMs !== 'number' || !Number.isFinite(i.nowMs)) throw new Error('planDeposits: clock must be a finite number');
  const seen = new Set<string>();
  for (const t of i.trusts) {
    if (typeof t !== 'string' || t.length === 0) throw new Error('planDeposits: empty trust id');
    if (seen.has(t)) throw new Error('planDeposits: duplicate trust id');
    seen.add(t);
  }
  const epoch = currentEpoch(i.nowMs);
  const epochStartMs = epoch * (wire as any).EPOCH_SECONDS * 1000;
  const due: DueDeposit[] = [];
  let next: number | null = null;
  for (const trustId of i.trusts) {
    if (i.done.has(depositKey(trustId, epoch))) continue;
    const r = await fraction(i.seed, trustId, epoch);
    const at = scheduleRedeposit({ epochStartMs, rand: () => r });
    if (at <= i.nowMs) due.push({ trustId, epoch, dueAtMs: at });
    else if (next === null || at < next) next = at;
  }
  if (next === null && i.trusts.length > 0) next = (epoch + 1) * (wire as any).EPOCH_SECONDS * 1000;
  return { due, nextAtMs: next };
}
