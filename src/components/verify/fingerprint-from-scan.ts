// Render-glass: pull a fingerprint out of a scanned QR payload, then compare
// it to the stored contact fingerprint. No network. Never logs the payload.
//
// Accepts only payloads that ARE a fingerprint (plain / grouped even-length hex
// ≥ 16, JSON.fingerprint, or ?fp= / ?fingerprint=). Invite/share URLs carry a
// key fragment in the hash — that is NOT a fingerprint, so they return null and
// the sheet fails loud. Canonical live ids are 64-hex; compare is byte-equal.

import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';

const MIN_HEX = 16;

function acceptHex(hex: string): string | null {
  if (hex.length >= MIN_HEX && hex.length % 2 === 0) return hex;
  return null;
}

function asUrl(raw: string): URL | null {
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
    if (hasScheme) return new URL(raw);
    if (/^[\w.-]+\.[a-z]{2,}([/:?#]|$)/i.test(raw)) return new URL(`https://${raw}`);
  } catch {
    /* not a URL */
  }
  return null;
}

/**
 * Extract a canonical hex fingerprint from untrusted QR text.
 * TOTAL: never throws. Returns null when the payload is not a fingerprint.
 */
export function extractFingerprintFromScan(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(trimmed) as { fingerprint?: unknown };
      if (typeof obj.fingerprint === 'string') {
        const fromJson = acceptHex(normalizeFingerprintHex(obj.fingerprint));
        if (fromJson) return fromJson;
      }
    } catch {
      /* not JSON — fall through */
    }
  }

  const url = asUrl(trimmed);
  if (url) {
    const q = url.searchParams.get('fp') || url.searchParams.get('fingerprint');
    if (!q) return null;
    return acceptHex(normalizeFingerprintHex(q));
  }

  return acceptHex(normalizeFingerprintHex(trimmed));
}

/**
 * Byte-equal compare after normalize (case / separators stripped).
 * Different lengths are a mismatch — never prefix-match.
 */
export function fingerprintsMatch(stored: string, scanned: string | null): boolean {
  if (!scanned) return false;
  const a = normalizeFingerprintHex(stored);
  const b = normalizeFingerprintHex(scanned);
  if (!a || !b || a.length !== b.length) return false;
  return a === b;
}
