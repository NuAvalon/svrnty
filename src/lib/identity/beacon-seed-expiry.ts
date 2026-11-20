// src/lib/identity/beacon-seed-expiry.ts
// #588 piece B (DARK): when a stored deposit seed stops being useful. Separate from beacon-seeds.ts so the main bundle's client-store does not
// import beacon-wire; the caller (the re-deposit loop, lazy) imports this one.
import { relayDeadAtMs } from '../crypto/beacon-relay-margin';

/** When a deposit for `epoch` stops being useful: the end of that epoch, plus one grace window, plus the relay's skew margin
 *  (epoch end + GRACE + RETENTION margin). The epoch and grace constants come from beacon-wire (the ONE definition) and the margin from
 *  beacon-relay-margin, so a device clock running ahead of the relay's cannot expire the seed that signs the withdraw while the relay
 *  still accepts deposits into the epoch. A seed already stored keeps the expiry it was minted with. */
export function expiryForEpoch(epoch: bigint): number {
  return relayDeadAtMs(epoch);
}
