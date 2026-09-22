// src/sw/gd-pathname.ts
// The SHARED asset-pathname + coverage convention for the §4 manifest (Athena's lane). Apollo owns the framing
// primitive (bundle-manifest.ts); this pins (a) THE exact-path string a static asset maps to, and (b) how a
// given request is COVERED. The divergence risk (#141748): the signer walk, the SW's request.url→pathname, and
// the watchtower fetch must all map a static asset to the BYTE-IDENTICAL path string, or per-asset SRI
// false-WARNs. This module is the SW half; the signer + watchtower mirror the same rule. Co-witnessed by Apollo
// + Flint via the path-canon KAT.
//
// COVERAGE MODEL (resolved empirically 9/22 — the running svrnty app):
//   svrnty is default-SSR Next15 but every render route is 'use client', so shells are PRERENDERED byte-stable
//   HTML (x-nextjs-prerender:1). /u/alice ≡ /u/bob byte-identical (slug read client-side) — a dynamic-param
//   route serves ONE byte-stable shell across infinite paths. Therefore:
//     • STATIC assets (/_next/static/**, /public files, /sw.js, /manifest.json) → EXACT-PATH SRI (manifestPath).
//     • SHELLS (~5 prerendered navigations) → CONTENT-HASH MEMBERSHIP, NOT path-keyed (one hash covers infinite
//       /u/<name> paths). The classifier routes navigations to 'shell'; the SW checks SHA256(served) ∈ shell-set.
//     • DYNAMIC (/api/*, /_next/image, /_next/data) → not covered (skip).
//   This supersedes the earlier spa-single/per-route SHELL_MODE — shells are content-addressed, not path-keyed.
//
// EXACT-PATH RULE (KAT-locked with the 3 walkers):
//   path = URL.pathname — origin-relative, leading '/', same-origin only.
//     • NO query, NO fragment (an asset's identity is its path, not a ?v= cache-buster or #frag).
//     • %-encoding AS-SERVED — never decodeURIComponent. All 3 walkers keep the identical served encoding;
//       decoding would let '/a%2Fb' and '/a/b' diverge/collide across walkers. Byte-sort + compare are
//       case-sensitive: '/Icon.png' ≠ '/icon.png'; served case must match built case exactly.

/** How a given request is verified. Static → exact-path SRI; shell → content-hash membership; dynamic → skip. */
export type AssetClass = 'static' | 'shell' | 'dynamic';

// Prefixes that are always dynamic (server-rendered / per-request) → never manifest-covered.
const DYNAMIC_PREFIXES = ['/api/', '/_next/image', '/_next/data'];
// The immutable build-asset prefix (content-hashed filenames) → always exact-path covered.
const STATIC_BUILD_PREFIX = '/_next/static/';

/**
 * Canonical manifest path for a same-origin STATIC subresource, or null if it is not an in-manifest same-origin
 * asset (cross-origin → not a T1 manifest asset by construction). u.pathname is already %-encoded as-served and
 * excludes query/fragment; it is returned WITHOUT decoding. This is the exact string the signer + watchtower
 * must also produce (the KAT subject). Keep this function byte-stable — a change here is a manifest flag-day.
 */
export function manifestPath(requestUrl: string, origin: string): string | null {
  let u: URL;
  try {
    u = new URL(requestUrl);
  } catch {
    return null;
  }
  if (u.origin !== origin) return null;
  // Do NOT decode. Do NOT strip a trailing slash. Do NOT collapse '//'. As-served, byte-for-byte.
  return u.pathname;
}

/**
 * Classify how a request must be verified. `isNavigation` comes from the fetch event (request.mode==='navigate'
 * || accept: text/html) — the same signal the existing sw.js uses. A navigation is a SHELL (content-membership);
 * a subresource is STATIC (exact-path SRI) iff it is under /_next/static/ or is a root/public file with an
 * extension (svg/png/json/js/woff2/...); everything else same-origin non-navigation is DYNAMIC (skip).
 *
 * The extension heuristic is safe for svrnty: every /public asset and every /_next/static chunk has an
 * extension, while routes ('/', '/u/alice') do not. Note: the classifier only decides the SW's verify MODE — it
 * is NOT a manifest input, so a misclassification cannot break bundle_hash agreement (only over-/under-check a
 * single request). The manifest entries + hashes are the source of truth for what is actually covered.
 */
export function classifyRequest(requestUrl: string, origin: string, isNavigation: boolean): AssetClass {
  let u: URL;
  try {
    u = new URL(requestUrl);
  } catch {
    return 'dynamic';
  }
  if (u.origin !== origin) return 'dynamic'; // cross-origin is out of the T1 manifest
  if (isNavigation) return 'shell';
  const p = u.pathname;
  if (DYNAMIC_PREFIXES.some((d) => p.startsWith(d))) return 'dynamic';
  if (p.startsWith(STATIC_BUILD_PREFIX)) return 'static';
  // root/public static files carry an extension; routes do not.
  if (/\.[A-Za-z0-9]+$/.test(p)) return 'static';
  return 'dynamic';
}

/**
 * Classify a MANIFEST ENTRY path (not a live request) into its coverage class, so the SW can split the accepted
 * manifest into the exact-path static set and the content-membership shell set. Differs from classifyRequest in
 * ONE case: a no-extension path here is a SHELL (a prerendered route the signer deliberately included, e.g. '/',
 * '/u/[name]'), whereas a no-extension non-navigation live request is dynamic/skip. Same prefix rules otherwise.
 */
export function manifestPathClass(path: string): AssetClass {
  if (DYNAMIC_PREFIXES.some((d) => path.startsWith(d))) return 'dynamic';
  if (path.startsWith(STATIC_BUILD_PREFIX)) return 'static';
  if (/\.[A-Za-z0-9]+$/.test(path)) return 'static';
  return 'shell';
}
