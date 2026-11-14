// src/lib/identity/beacon-seed-expiry.ts
// #588 piece B (DARK): when a stored deposit seed stops being useful. Separate from beacon-seeds.ts so the main bundle's client-store does not
// import beacon-wire; the caller (the re-deposit loop, lazy) imports this one.
import * as wire from '../crypto/beacon-wire.mjs';

/** When a deposit for `epoch` stops being useful: the end of that epoch plus one grace window. Both constants come from beacon-wire (the ONE definition). */
export function expiryForEpoch(epoch: bigint): number {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- the wire module is untyped .mjs
  const w = wire as any;
  return (Number(epoch) + 1) * w.EPOCH_SECONDS * 1000 + w.GRACE_SECONDS * 1000;
}
