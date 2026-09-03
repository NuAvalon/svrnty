// src/lib/invite/parseInviteUrl.ts
//
// The ONE untrusted-input boundary for svrnty invite links (INV-4).
// Every entry point that takes an externally-supplied invite string — the paste field
// (JoinByCode), a future QR camera (ScanToJoin), the /c/[code] route — parses it HERE and
// only here, so there is a single validated path into the join ceremony (gate-3 as
// code). TOTAL: never throws; returns null on anything malformed or off-host. Rejection
// happens BEFORE any JoinerCeremony mount.
//
// SECURITY (INV-5 — the non-obvious one): the keyFragment is AES key material carried in
// the URL #hash (hashes are never sent to a server, by design). Callers MUST NOT log /
// echo / relay / persist the returned keyFragment beyond the ceremony, and MUST NOT echo
// the RAW INPUT in an error (it contains the fragment). An error may surface `code` at
// most. This parser never logs and never returns the raw input — it only extracts.

export interface ParsedInvite {
  code: string;
  keyFragment: string;
}

// Hosts an invite link is accepted for. The app's OWN host is always accepted (so the
// /c/ route and any deployment host — dev/prod/preview — work); the known svrnty hosts
// cover a link pasted on a sibling deployment. Any other host is rejected (INV-4
// wrong-host). Note: relay resolution always runs against the CURRENT app's relay via the
// `code`, never the pasted host — the host-pin is defense-in-depth against a lookalike
// link, not the resolution mechanism.
const KNOWN_HOSTS = new Set(['svrnty.is', 'www.svrnty.is', 'dev.svrnty.is']);

// Relay shortcodes are short, URL-safe, bounded. Permissive but capped — a path segment
// that isn't a plausible code is rejected rather than handed to the ceremony.
const CODE_RE = /^[A-Za-z0-9_-]{1,64}$/;

function hostAllowed(hostname: string): boolean {
  if (KNOWN_HOSTS.has(hostname)) return true;
  try {
    if (typeof window !== 'undefined' && window.location && window.location.hostname === hostname) {
      return true;
    }
  } catch {
    /* non-browser context — fall through to the known-host allowlist only */
  }
  return false;
}

/**
 * Parse a pasted/scanned svrnty invite link into { code, keyFragment }, or null.
 * Accepts a full URL with or without a scheme (e.g. "dev.svrnty.is/c/abc#key"). The key
 * lives only in the #fragment. TOTAL — malformed / off-host / missing-key → null, no throw.
 */
export function parseInviteUrl(input: unknown): ParsedInvite | null {
  if (typeof input !== 'string') return null;
  const raw = input.trim();
  if (!raw) return null;
  try {
    // Accept scheme-less pastes by defaulting to https (the only scheme our links use).
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
    const url = new URL(hasScheme ? raw : `https://${raw}`);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (!hostAllowed(url.hostname)) return null;
    // Path must be exactly /c/<code> (optional trailing slash).
    const m = url.pathname.match(/^\/c\/([^/]+)\/?$/);
    if (!m) return null;
    const code = decodeURIComponent(m[1]);
    if (!CODE_RE.test(code)) return null;
    // Key material lives in the #fragment. Require it; bound it; reject whitespace.
    const keyFragment = url.hash.startsWith('#') ? url.hash.slice(1) : '';
    if (!keyFragment || keyFragment.length > 1024 || /\s/.test(keyFragment)) return null;
    return { code, keyFragment };
  } catch {
    return null; // TOTAL — never throw on untrusted input
  }
}
