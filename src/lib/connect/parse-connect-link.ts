// src/lib/connect/parse-connect-link.ts
//
// Untrusted-input parse for one-step Connect-UX (CURSOR_QUEUE #3).
// Full invites with a #key still go through parseInviteUrl (INV-4) first.
// This parser ALSO accepts a bare /c/{code} and a bare code — those have no
// key fragment; resolve stays behind the add-logic stub (Apollo post-flip).
//
// INV-5: keyFragment is key material. Never log / echo / interpolate the raw
// paste or the fragment. This module never returns the raw input.

import { parseInviteUrl } from '../invite/parseInviteUrl';

export type ParsedConnectLink = {
  code: string;
  /** AES key material when the paste included a #fragment. NEVER log or echo. */
  keyFragment: string | null;
};

const KNOWN_HOSTS = new Set(['svrnty.is', 'www.svrnty.is', 'dev.svrnty.is']);
const CODE_RE = /^[A-Za-z0-9_-]{1,64}$/;

function hostAllowed(hostname: string): boolean {
  if (KNOWN_HOSTS.has(hostname)) return true;
  try {
    if (typeof window !== 'undefined' && window.location?.hostname === hostname) {
      return true;
    }
  } catch {
    /* non-browser — known-host allowlist only */
  }
  return false;
}

/**
 * Parse a pasted connect link or bare grow-code.
 * TOTAL — malformed / off-host / empty → null, never throws.
 */
export function parseConnectLink(input: unknown): ParsedConnectLink | null {
  if (typeof input !== 'string') return null;
  const raw = input.trim();
  if (!raw) return null;

  // Bare code (no path, no fragment).
  if (CODE_RE.test(raw)) {
    return { code: raw, keyFragment: null };
  }

  const invite = parseInviteUrl(raw);
  if (invite) {
    return { code: invite.code, keyFragment: invite.keyFragment };
  }

  // URL without a key fragment — parseInviteUrl rejects those (ceremony needs the key).
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
    const url = new URL(hasScheme ? raw : `https://${raw}`);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (!hostAllowed(url.hostname)) return null;
    const m = url.pathname.match(/^\/c\/([^/]+)\/?$/);
    if (!m) return null;
    const code = decodeURIComponent(m[1]);
    if (!CODE_RE.test(code)) return null;
    const frag = url.hash.startsWith('#') ? url.hash.slice(1) : '';
    if (frag && (frag.length > 1024 || /\s/.test(frag))) return null;
    return { code, keyFragment: frag || null };
  } catch {
    return null;
  }
}
