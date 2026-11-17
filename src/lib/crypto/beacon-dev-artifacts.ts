// src/lib/crypto/beacon-dev-artifacts.ts: #822 (a)-Z, the DEV-ONLY proving-file pin. DARK: nothing in the app imports this module yet.
//
// beacon-artifacts.ts refuses to load a proving key until the production ceremony's zkey hash is pinned (PINS.zkeySha256 is null, so 'zkey-unpinned'). That is the
// right behaviour everywhere except a dev deploy that has to prove something so the trust wire can be tested end to end. This module is the ONLY place a
// non-ceremony zkey is named, and it hands it out in a dev build that opted in, never otherwise.
//
// THE KEY IS A REHEARSAL KEY. Its toxic waste is known, so anyone can forge a proof against it. It must never be reachable from a production build: not "unreachable
// at run time" but ABSENT from the built JS. The selection below is a STATIC branch on NEXT_PUBLIC_BEACON_DEV_ARTIFACTS, which next.config.ts ALWAYS defines ('true' only
// in a dev build that opted in; see beacon-dev-flag.ts), so every other build has `'' === 'true'` and the minifier drops the whole block with the hash and the URLs in it.
// (A branch on an UNSET NEXT_PUBLIC_ variable is NOT dropped: measured.) A second, run-time check (isBeaconWireLive) is behind it as defence in depth.
//
// The files themselves are served by the dev deploy only, from /beacon-dev/ on the dev origin, and are never placed in public/ (a production build copies public/).
// Everything else keeps the existing behaviour: PINS stays null and loadProvingFiles throws 'zkey-unpinned'.

import { isBeaconWireLive } from '@/lib/claim-gates';
import { PINS, type ArtifactPins } from './beacon-artifacts';

export interface BeaconArtifactConfig {
  pins: ArtifactPins;
  urls: { wasm: string; zkey: string };
}

/**
 * The pins and URLs for a DEV build that opted in to the beacon wire, else null (the caller then uses PINS, which refuses). The wasm pin is the production one
 * (the circuit is the same); only the zkey pin differs, and it is the rehearsal chain's final.zkey (sha256 below, 4,164,155 bytes).
 */
export function devBeaconArtifacts(): BeaconArtifactConfig | null {
  if (process.env.NEXT_PUBLIC_BEACON_DEV_ARTIFACTS === 'true') {
    if (isBeaconWireLive()) {
      return {
        pins: {
          wasmSha256: PINS.wasmSha256,
          zkeySha256: 'b13ee7020226548a0e13738db48075aae27048d09217d8ca4bd5b6458d9016f6',
        },
        urls: { wasm: '/beacon-dev/slotbind.wasm', zkey: '/beacon-dev/final.zkey' },
      };
    }
  }
  return null;
}
