// src/lib/config/domain.ts
// Single source of truth for the deployment's domain — the ONE knob a self-hoster sets.
//
// Self-host (packaging / git-infra §3 dumb-relay-exportable-container): set
//   NEXT_PUBLIC_SVRNTY_DOMAIN=id.example.com
// and every share link, claimed-slug URL, and display string points at YOUR domain — no
// code fork, no protocol fork. Default = svrnty.is (the managed nursery). "The tree in the
// seed": svrnty.is is a DEFAULT, not a dependency; a self-certifying durable_id needs no
// permission from svrnty.is to relocate.
//
// NEXT_PUBLIC_* is inlined into the client bundle at build time by Next, so this reads
// correctly both server- and client-side. The typeof guard keeps it safe in any runtime.

/** The bare domain (no scheme), e.g. 'svrnty.is' or a self-hoster's 'id.example.com'. */
export const SVRNTY_DOMAIN: string =
  (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_SVRNTY_DOMAIN) || 'svrnty.is';

/**
 * The base URL WITH scheme, e.g. 'https://svrnty.is'. Derived from SVRNTY_DOMAIN unless
 * explicitly overridden (NEXT_PUBLIC_SVRNTY_BASE_URL) — e.g. for http/localhost in dev.
 */
export const SVRNTY_BASE_URL: string =
  (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_SVRNTY_BASE_URL) ||
  `https://${SVRNTY_DOMAIN}`;

/**
 * A shortcode share link WITH scheme: `${base}/c/${code}#${keyFragment}`.
 * The key fragment lives after '#' and never reaches the server (client-only decryption).
 */
export function shareUrl(code: string, keyFragment: string): string {
  return `${SVRNTY_BASE_URL}/c/${code}#${keyFragment}`;
}

/** A scheme-less share link for display, e.g. 'svrnty.is/c/ABC123' (optionally with key). */
export function shareUrlShort(code: string, keyFragment?: string): string {
  return keyFragment ? `${SVRNTY_DOMAIN}/c/${code}#${keyFragment}` : `${SVRNTY_DOMAIN}/c/${code}`;
}

/** A scheme-less claimed-slug URL for display, e.g. 'svrnty.is/alice'. */
export function slugUrlShort(slug: string): string {
  return `${SVRNTY_DOMAIN}/${slug}`;
}
