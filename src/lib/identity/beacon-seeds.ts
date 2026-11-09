// src/lib/identity/beacon-seeds.ts
// #588 piece B (DARK; nothing imports it): the one-time deposit seeds the client keeps so it can sign a LATER poll/withdraw under the deposit's K.
// This file is the PURE half: validation, map operations, expiry. The encrypted-at-rest storage (getBeaconSeeds / setBeaconSeeds) is in client-store.ts,
// using the same AAD-bound path as the suppression and held-affirmatives records. A seed is a secret: it never leaves this device and is not part of the
// .svrnty backup (packVault takes an explicit contents object); after a restore the client simply re-deposits.
// No beacon-wire import here on purpose: client-store imports this file statically (main bundle); the epoch maths lives in beacon-seed-expiry.ts.
/** Most seeds held at once. A deposit per pending trust per epoch, plus the grace overlap: far below this for any real book. */
export const MAX_SEEDS = 2048;
const SEED_BYTES = 32;
const CANON = /^(0|[1-9][0-9]{0,76})$/;

export interface BeaconSeedEntry {
  /** The epoch the deposit was made for, canonical decimal. */
  epoch: string;
  /** The deposit's public slot and nullifier (canonical decimals): with the seed they let the client sign poll/withdraw for exactly this deposit. */
  H_e: string;
  N: string;
  /** The one-time Ed25519 seed, base64 of exactly 32 bytes. */
  seed: string;
  /** Wall-clock ms after which the seed is useless and is swept. */
  expiresAtMs: number;
}
export type BeaconSeeds = Record<string, BeaconSeedEntry>;

/** The map key: H_e:N, both canonical decimals. Throws on anything else (the key is a storage identity: no aliases). */
export function seedKey(H_e: string, N: string): string {
  if (typeof H_e !== 'string' || !CANON.test(H_e) || typeof N !== 'string' || !CANON.test(N)) throw new Error('seedKey: H_e and N must be canonical decimals');
  return `${H_e}:${N}`;
}

function seedBytesOk(b64: unknown): boolean {
  if (typeof b64 !== 'string' || b64.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/.test(b64)) return false;
  try { return atob(b64).length === SEED_BYTES && btoa(atob(b64)) === b64; } catch { return false; }
}

function entryOk(e: unknown): e is BeaconSeedEntry {
  if (!e || typeof e !== 'object' || Array.isArray(e)) return false;
  const o = e as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 5 || !['epoch', 'H_e', 'N', 'seed', 'expiresAtMs'].every((k) => keys.includes(k))) return false;
  return typeof o.epoch === 'string' && CANON.test(o.epoch) && typeof o.H_e === 'string' && CANON.test(o.H_e) && typeof o.N === 'string' && CANON.test(o.N)
    && seedBytesOk(o.seed) && typeof o.expiresAtMs === 'number' && Number.isFinite(o.expiresAtMs) && o.expiresAtMs >= 0;
}

/** Strict shape check for a map read back from storage: every key is H_e:N of ITS OWN entry, every entry is exactly the five fields. */
export function isBeaconSeeds(x: unknown): x is BeaconSeeds {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  for (const [k, v] of Object.entries(x as Record<string, unknown>)) {
    if (!entryOk(v)) return false;
    if (k !== `${v.H_e}:${v.N}`) return false;
  }
  return true;
}

/** A NEW map with the entry added. Idempotent for the same seed; refuses a different seed under the same (H_e, N) (overwriting would strand a live
 * deposit) and refuses to grow past MAX_SEEDS. The input is never mutated. */
export function addSeed(map: BeaconSeeds, e: BeaconSeedEntry): BeaconSeeds {
  if (!entryOk(e)) throw new Error('addSeed: invalid entry');
  const k = seedKey(e.H_e, e.N);
  const cur = map[k];
  if (cur) {
    if (cur.seed !== e.seed) throw new Error('addSeed: conflict, a different seed is already held for this deposit');
    return { ...map };
  }
  if (Object.keys(map).length >= MAX_SEEDS) throw new Error('addSeed: full');
  return { ...map, [k]: { epoch: e.epoch, H_e: e.H_e, N: e.N, seed: e.seed, expiresAtMs: e.expiresAtMs } };
}

/** A NEW map without the deposit (tolerates a missing one). */
export function removeSeed(map: BeaconSeeds, H_e: string, N: string): BeaconSeeds {
  const k = seedKey(H_e, N);
  if (!(k in map)) return { ...map };
  const { [k]: _gone, ...rest } = map;
  return rest;
}

/** Drop entries whose expiry is strictly BEFORE now (expiry == now is still usable). */
export function sweepExpired(map: BeaconSeeds, nowMs: number): { kept: BeaconSeeds; removed: number } {
  const kept: BeaconSeeds = {};
  let removed = 0;
  for (const [k, v] of Object.entries(map)) {
    if (v.expiresAtMs < nowMs) removed++;
    else kept[k] = v;
  }
  return { kept, removed };
}
