/**
 * Validate a typed relay URL: GET {url}/health must be 200 + a full svrnty satellite.
 * Reasons match Flint's spec exactly.
 */

import { RELAY_COPY } from './relay-copy';

export type RelayHealthReason =
  | typeof RELAY_COPY.invalid.reach
  | typeof RELAY_COPY.invalid.notRelay
  | typeof RELAY_COPY.invalid.registrationOnly;

export type RelayHealth =
  | { ok: true; url: string; service: string; mode?: string }
  | { ok: false; url: string; reason: RelayHealthReason };

const HEALTH_MS = 8_000;

export function normalizeRelayUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  parsed.hash = '';
  parsed.search = '';
  const path = parsed.pathname.replace(/\/+$/, '');
  parsed.pathname = path || '/';
  return parsed.toString().replace(/\/$/, '');
}

function asRecord(body: unknown): Record<string, unknown> | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  return body as Record<string, unknown>;
}

export async function validateRelayHealth(
  raw: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RelayHealth> {
  const url = normalizeRelayUrl(raw);
  if (!url) {
    return { ok: false, url: raw.trim(), reason: RELAY_COPY.invalid.scheme };
  }

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), HEALTH_MS);
  try {
    const res = await fetchImpl(`${url}/health`, {
      method: 'GET',
      signal: ctrl.signal,
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      return { ok: false, url, reason: RELAY_COPY.invalid.reach };
    }
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      return { ok: false, url, reason: RELAY_COPY.invalid.notRelay };
    }
    const rec = asRecord(body);
    if (!rec) return { ok: false, url, reason: RELAY_COPY.invalid.notRelay };

    const service = String(rec.service || '').toLowerCase();
    const mode = String(rec.mode || '').toLowerCase();
    const status = String(rec.status || '').toLowerCase();

    if (service === 'registration') {
      return { ok: false, url, reason: RELAY_COPY.invalid.registrationOnly };
    }
    if (service !== 'satellite') {
      return { ok: false, url, reason: RELAY_COPY.invalid.notRelay };
    }
    if (mode && mode !== 'full') {
      return { ok: false, url, reason: RELAY_COPY.invalid.registrationOnly };
    }
    if (status && status !== 'online') {
      return { ok: false, url, reason: RELAY_COPY.invalid.reach };
    }
    return { ok: true, url, service, mode: mode || 'full' };
  } catch {
    return { ok: false, url, reason: RELAY_COPY.invalid.reach };
  } finally {
    clearTimeout(t);
  }
}
