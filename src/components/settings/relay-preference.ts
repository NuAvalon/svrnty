/**
 * Glass-side chosen-relay preference.
 * Apollo wires this into fetch callers (override default /api/relay).
 * The UI only writes current after a completed migrate — never on type-ahead.
 */

import { SVRNTY_BASE_URL } from '@/lib/config/domain';

export const RELAY_PREFERENCE_KEY = 'svrnty.relay.url.v1';
export const DEFAULT_RELAY_PATH = '/api/relay';

export function defaultRelayUrl(): string {
  if (typeof window !== 'undefined' && window.location?.origin) {
    return `${window.location.origin}${DEFAULT_RELAY_PATH}`;
  }
  return `${SVRNTY_BASE_URL}${DEFAULT_RELAY_PATH}`;
}

export function readChosenRelayUrl(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(RELAY_PREFERENCE_KEY);
    const url = (raw || '').trim();
    return url || null;
  } catch {
    return null;
  }
}

export function writeChosenRelayUrl(url: string): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(RELAY_PREFERENCE_KEY, url.trim());
}

/** What the Settings screen shows as current. */
export function currentRelayUrl(): string {
  return readChosenRelayUrl() || defaultRelayUrl();
}
