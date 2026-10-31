// src/lib/satellite/satellite-base-url.ts
// Where the /api/satellite/* proxy routes forward to, with an environment fence (Flint lane #2583, Archie #2588 (3)).
// Prod and dev stacks share the outpost-web docker network, so `dev-satellite` / `dev-registration` resolve from the PROD container.
// One wrong SATELLITE_URL on prod would then send prod users' requests (bind: fingerprint + signing key; PSI) to a DEV service, and
// the dev PSI pin would even match. The headless path already refuses this (know-psi.ts assertDevOnly); this is the server half.
//
// Rule: a build is DEV only when its domain (NEXT_PUBLIC_SVRNTY_DOMAIN, inlined at build) starts with "dev." (dev.svrnty.is).
// Every other build counts as prod, so an unset or unknown domain fails closed. A non-dev build refuses a satellite host whose first
// label starts with "dev" (dev-satellite, dev-registration, dev.svrnty.is) and refuses a URL it can't parse.

export const DEFAULT_SATELLITE_URL = 'http://registration:8101';

export class SatelliteEnvRefused extends Error {
  constructor(reason: string) {
    super(`satellite URL refused: ${reason}`);
    this.name = 'SatelliteEnvRefused';
  }
}

export function isDevBuild(domain: string | undefined): boolean {
  return typeof domain === 'string' && domain.toLowerCase().startsWith('dev.');
}

function isDevHost(hostname: string): boolean {
  const first = hostname.toLowerCase().split('.')[0] ?? '';
  return first === 'dev' || first.startsWith('dev-');
}

/**
 * The satellite base URL for this build, or THROWS SatelliteEnvRefused. The proxy routes call it inside their existing try, so a
 * refusal answers like an unavailable service and nothing is forwarded.
 */
export function satelliteBaseUrl(
  env: { SATELLITE_URL?: string; NEXT_PUBLIC_SVRNTY_DOMAIN?: string } = {
    SATELLITE_URL: process.env.SATELLITE_URL,
    NEXT_PUBLIC_SVRNTY_DOMAIN: process.env.NEXT_PUBLIC_SVRNTY_DOMAIN,
  },
): string {
  const url = env.SATELLITE_URL || DEFAULT_SATELLITE_URL;
  if (isDevBuild(env.NEXT_PUBLIC_SVRNTY_DOMAIN)) return url;
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    throw new SatelliteEnvRefused('not a URL');
  }
  if (!host || isDevHost(host)) {
    console.error('[satellite] refusing a dev satellite host in a non-dev build; nothing forwarded');
    throw new SatelliteEnvRefused('a dev host in a non-dev build');
  }
  return url;
}
