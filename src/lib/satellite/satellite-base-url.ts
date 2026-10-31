// src/lib/satellite/satellite-base-url.ts
// Where the /api/satellite/* proxy routes forward to, with an environment fence (Flint lane #2583, Archie #2588 (3)).
// Prod and dev stacks share the outpost-web docker network, so `dev-satellite` / `dev-registration` resolve from the PROD container.
// One wrong SATELLITE_URL on prod would then send prod users' requests (bind: fingerprint + signing key; PSI) to a DEV service, and
// the dev PSI pin would even match. The headless path already refuses this (know-psi.ts assertDevOnly); this is the server half.
//
// Rule: a build is DEV only when its domain (NEXT_PUBLIC_SVRNTY_DOMAIN, inlined at build) starts with "dev." (dev.svrnty.is).
// Every other build counts as prod, so an unset or unknown domain fails closed. A non-dev build forwards ONLY to an ALLOWLIST of
// hosts (Flint #2602, Archie #2607): the prod stack's service names, or SATELLITE_ALLOWED_HOSTS (comma-separated) for a self-hoster.
// Anything else is refused: a dev-* name, a lookalike ("devsatellite"), an IP literal (a dev container's address on the shared
// network), a URL that doesn't parse, a non-http(s) scheme.

export const DEFAULT_SATELLITE_URL = 'http://registration:8101';

/** The prod stack's own satellite/registration services (docker-compose.yml). */
export const PROD_SATELLITE_HOSTS: readonly string[] = ['registration', 'satellite', 'outpost-registration', 'outpost-satellite'];

export class SatelliteEnvRefused extends Error {
  constructor(reason: string) {
    super(`satellite URL refused: ${reason}`);
    this.name = 'SatelliteEnvRefused';
  }
}

export function isDevBuild(domain: string | undefined): boolean {
  return typeof domain === 'string' && domain.toLowerCase().startsWith('dev.');
}

function allowedHosts(extra: string | undefined): Set<string> {
  const out = new Set(PROD_SATELLITE_HOSTS);
  for (const h of (extra ?? '').split(',')) {
    const t = h.trim().toLowerCase();
    if (t) out.add(t);
  }
  return out;
}

/**
 * The satellite base URL for this build, or THROWS SatelliteEnvRefused. The proxy routes call it inside their existing try, so a
 * refusal answers like an unavailable service and nothing is forwarded.
 */
export function satelliteBaseUrl(
  env: { SATELLITE_URL?: string; NEXT_PUBLIC_SVRNTY_DOMAIN?: string; SATELLITE_ALLOWED_HOSTS?: string } = {
    SATELLITE_URL: process.env.SATELLITE_URL,
    NEXT_PUBLIC_SVRNTY_DOMAIN: process.env.NEXT_PUBLIC_SVRNTY_DOMAIN,
    SATELLITE_ALLOWED_HOSTS: process.env.SATELLITE_ALLOWED_HOSTS,
  },
): string {
  const url = env.SATELLITE_URL || DEFAULT_SATELLITE_URL;
  if (isDevBuild(env.NEXT_PUBLIC_SVRNTY_DOMAIN)) return url;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SatelliteEnvRefused('not a URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new SatelliteEnvRefused('not http(s)');
  // URL.hostname is already lowercased. An IP literal is refused even if someone lists it: an address on the shared docker
  // network says nothing about which stack it belongs to (Archie #2607).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) || parsed.hostname.startsWith('[')) {
    throw new SatelliteEnvRefused('an IP literal in a non-dev build');
  }
  if (!allowedHosts(env.SATELLITE_ALLOWED_HOSTS).has(parsed.hostname)) {
    console.error('[satellite] refusing a satellite host that is not on this build\'s allowlist; nothing forwarded');
    throw new SatelliteEnvRefused('host not on the allowlist for a non-dev build');
  }
  return url;
}
