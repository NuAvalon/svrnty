// src/lib/beacon-dev-flag.ts: #822 (a)-Z. The ONE build-time switch for the dev-only beacon proving files. Pure: no I/O, no clock.
//
// WHY THIS EXISTS: next.config.ts inlines the result below as NEXT_PUBLIC_BEACON_DEV_ARTIFACTS ('true' or ''), a variable that is ALWAYS defined. Next.js does not inline an UNSET
// NEXT_PUBLIC_ variable (measured with real production builds: the rehearsal zkey hash and URLs stayed in the bundle of a build with nothing set), so a branch guarded by
// `process.env.NEXT_PUBLIC_BEACON_LIVE === 'true'` is NOT dropped from a production build. Defining the constant always makes `'' === 'true'` a compile-time false, and the minifier
// removes the block and everything in it.
//
// IT IS THE SAME PREDICATE as isBeaconWireLive() (claim-gates.ts): a dev build (isDevBuild on the domain) AND the explicit opt-in. beacon-dev-flag.test.ts proves they agree on a grid.

import { isDevBuild } from './satellite/satellite-base-url';

export function beaconDevArtifactsFlag(env: Record<string, string | undefined>): 'true' | '' {
  return isDevBuild(env.NEXT_PUBLIC_SVRNTY_DOMAIN) && env.NEXT_PUBLIC_BEACON_LIVE === 'true' ? 'true' : '';
}
