// PSI discovery start, gate FIRST. buildPsiSyncOptions POSTs the user's fingerprint + sign pubkey to `${satellite}/bind` before it ever
// checks the satellite key pin (know-layer-sync.ts runBindCeremony), so the build-time gate has to be consulted before it is called at all:
// a gated-off build must make ZERO requests to /api/satellite (Flint #2583, Archie #2588). Pure seam: ContactManagement is the only caller.

import { isPSIDiscoveryLive } from '@/lib/claim-gates';
import { buildPsiSyncOptions, startKnowLayerSync } from '@/lib/sync/know-layer-sync';

export interface PsiDiscoveryHandle {
  stop: () => void;
}

export interface PsiDiscoveryDeps {
  gate?: () => boolean;
  build?: typeof buildPsiSyncOptions;
  start?: typeof startKnowLayerSync;
  /** True once the caller has gone away (effect cleanup): checked after the async build, so nothing starts for a stale caller. */
  cancelled?: () => boolean;
}

/** Starts PSI discovery for `identity`, or returns null without touching the network when the gate is off or no options could be built. */
export async function startPsiDiscovery(identity: unknown, deps: PsiDiscoveryDeps = {}): Promise<PsiDiscoveryHandle | null> {
  if (!(deps.gate ?? isPSIDiscoveryLive)()) return null;
  const options = await (deps.build ?? buildPsiSyncOptions)(identity as Parameters<typeof buildPsiSyncOptions>[0]);
  if (!options || deps.cancelled?.()) return null;
  return (deps.start ?? startKnowLayerSync)(identity as Parameters<typeof startKnowLayerSync>[0], options);
}
