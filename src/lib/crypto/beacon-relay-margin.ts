// src/lib/crypto/beacon-relay-margin.ts: when a row of an epoch can no longer be matched at the relay, as THIS device can know it.
//
// The relay decides an epoch is closed by ITS clock; this device only has its own. A device clock that runs fast would call an epoch closed
// while the relay still accepts deposits into it, and every place that acts on "closed" (dropping a row, giving up on its withdraw, releasing
// the one-time seed that signs the withdraw, letting that seed expire) would act early. So "closed" here means closed by the relay's own rule
// PLUS the relay's own skew allowance, and every such place takes it from this one module.
import * as wire from './beacon-wire.mjs';

/** The relay's skew allowance past an epoch's last open window: clock skew, plus a deposit that was verifying as the window closed.
 *  This is the value of RETENTION_MARGIN_S in infra/svrnty/beacon_centurion.py, and it is NOT a second definition: a test reads that file
 *  and fails if the two differ. A device clock fast by MORE than this can still act early (a bound, stated in the docs). */
export const RELAY_CLOSE_MARGIN_SECONDS = 3600;

/** The instant (ms) from which a row of `epoch` is dead as far as this device can tell: the end of that epoch, plus the grace window the relay
 *  keeps the old epoch open for, plus the skew margin. Before it the relay may still accept a deposit into the epoch, so the row may still
 *  be matched and its withdraw may still matter. */
export function relayDeadAtMs(epoch: number | bigint | string): number {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- the wire module is untyped .mjs
  const w = wire as any;
  return (Number(epoch) + 1) * w.EPOCH_SECONDS * 1000 + (w.GRACE_SECONDS + RELAY_CLOSE_MARGIN_SECONDS) * 1000;
}

/** True from the instant `relayDeadAtMs(epoch)` on. Never true for the current epoch or a later one. */
export function relayDead(epoch: number | bigint | string, nowMs: number): boolean {
  return nowMs >= relayDeadAtMs(epoch);
}
