/**
 * Relay endpoint configuration — device-level, UI-only (localStorage).
 *
 * "Set your relay" (Peter #135726: self-host from day 1 → it's only decentralized if you
 * can point your client at a relay you run). The client talks to a relay for its mailbox
 * (deposit / poll / ack) and the shortcode dead-drop. By DEFAULT that relay is the app's
 * own bundled `/api/relay` (same-origin Next routes) — nothing changes for someone who
 * doesn't self-host. A self-hoster points the client at THEIR relay (e.g.
 * https://relay.duskworks.io); this module holds that choice and `resolveRelayBase()`
 * feeds it to the transport/sync layer's `relayBase` param.
 *
 * ⛔ SECURITY SEAM (Flint): this module holds NO identities and NO secrets — only a base
 * URL. It never touches session crypto. The relay is content-blind (every payload is a
 * sealed blob), so choosing a relay does NOT change what a relay can read — only who
 * carries the ciphertext. `isValidRelayBase()` is the client-side allow-check (https-only
 * off-localhost, no embedded credentials, http(s) schemes only) — Flint owns tightening it
 * and the relay's own CORS/allow-origin posture for direct client→relay calls.
 *
 * Scope (Athena #135785, per Peter): single relay per user, NOT federation. Switching
 * relays (with mailbox migration) is Athena's relay-side concern; this module only records
 * WHICH relay the client uses.
 */

export const RELAY_CONFIG_KEY = 'svrnty.relay-config';

/** The app's own bundled relay: the same-origin Next routes under /api/relay. Default. */
export const BUNDLED_RELAY_BASE = '/api/relay';

export type RelayConfig = {
  /**
   * Base the client prefixes onto the relay paths (`${relayBase}/envelope`, `/queue`,
   * `/ack`). Either the same-origin bundled default ('/api/relay') or an absolute origin
   * for a self-hosted relay. No trailing slash (normalized on save).
   */
  relayBase: string;
};

export const DEFAULT_RELAY_CONFIG: RelayConfig = {
  relayBase: BUNDLED_RELAY_BASE,
};

/** True once the user has pointed at a relay other than the bundled one. */
export function isCustomRelay(config: RelayConfig): boolean {
  return config.relayBase !== BUNDLED_RELAY_BASE;
}

/**
 * Client-side allow-check for a relay base the user typed/pasted. The relay's OWN posture
 * (CORS / origin allow-list for direct client calls) is Athena's + Flint's server concern;
 * this only rejects the obviously-unsafe or malformed before we persist it.
 *
 * Accepts: the bundled same-origin default, OR an absolute http(s) URL that is https
 * (plain http allowed ONLY for loopback self-host testing), carries no embedded
 * credentials, and uses no scheme other than http/https.
 */
export function isValidRelayBase(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === BUNDLED_RELAY_BASE) return true;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
  // Never carry credentials in the relay URL — they'd persist in localStorage in the clear.
  if (url.username || url.password) return false;
  const isLoopback =
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '[::1]';
  // https everywhere except loopback (a self-hoster testing on their own machine).
  if (url.protocol === 'http:' && !isLoopback) return false;
  return true;
}

/**
 * Normalize a valid relay base for storage/use: trim and strip a trailing slash so
 * `${relayBase}/envelope` never doubles the separator. The bundled default is returned
 * verbatim. Assumes `isValidRelayBase(value)` — call that first.
 */
export function normalizeRelayBase(value: string): string {
  const trimmed = value.trim();
  if (trimmed === BUNDLED_RELAY_BASE) return trimmed;
  return trimmed.replace(/\/+$/, '');
}

export function parseRelayConfig(raw: string | null): RelayConfig {
  if (!raw) return { ...DEFAULT_RELAY_CONFIG };
  try {
    const parsed = JSON.parse(raw) as Partial<RelayConfig>;
    const candidate = parsed.relayBase;
    if (typeof candidate === 'string' && isValidRelayBase(candidate)) {
      return { relayBase: normalizeRelayBase(candidate) };
    }
    return { ...DEFAULT_RELAY_CONFIG };
  } catch {
    return { ...DEFAULT_RELAY_CONFIG };
  }
}

export function readRelayConfig(): RelayConfig {
  if (typeof localStorage === 'undefined') return { ...DEFAULT_RELAY_CONFIG };
  try {
    return parseRelayConfig(localStorage.getItem(RELAY_CONFIG_KEY));
  } catch {
    return { ...DEFAULT_RELAY_CONFIG };
  }
}

/**
 * Persist a relay choice. Returns the config actually stored (normalized), or throws
 * `RangeError` if the base fails the allow-check — callers surface that as a validation
 * error in the "set relay" UI rather than silently falling back.
 */
export function writeRelayConfig(config: RelayConfig): RelayConfig {
  if (!isValidRelayBase(config.relayBase)) {
    throw new RangeError(`Invalid relay base: ${config.relayBase}`);
  }
  const normalized: RelayConfig = { relayBase: normalizeRelayBase(config.relayBase) };
  if (typeof localStorage === 'undefined') return normalized;
  try {
    localStorage.setItem(RELAY_CONFIG_KEY, JSON.stringify(normalized));
  } catch {
    /* ignore quota / private mode — the in-memory return is still authoritative for this tick */
  }
  return normalized;
}

/** Reset to the bundled relay (used by "use the built-in relay" in the UI). */
export function clearRelayConfig(): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.removeItem(RELAY_CONFIG_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * The single accessor the transport/sync layer reads to get the current relay base.
 * Everything that today defaults `relayBase ?? '/api/relay'` should instead pass
 * `resolveRelayBase()` so the user's choice actually takes effect.
 */
export function resolveRelayBase(): string {
  return readRelayConfig().relayBase;
}

/** Host label for display (bundled default reads as "the built-in relay"). */
export function relayHostLabel(config: RelayConfig): string {
  if (!isCustomRelay(config)) return 'the built-in relay';
  try {
    return new URL(config.relayBase).host;
  } catch {
    return config.relayBase;
  }
}

/**
 * Claim-honest one-liner for the "set relay" panel. Says exactly what is true: which relay
 * carries your (sealed) messages, and that switching relays doesn't change what a relay can
 * read. Never implies the relay is trusted with content.
 */
export function relayStatusLine(config: RelayConfig): string {
  if (!isCustomRelay(config)) {
    return 'Using the built-in relay. Your messages are sealed before they leave your device — no relay can read them.';
  }
  return `Using your relay at ${relayHostLabel(config)}. Your messages are sealed before they leave your device — the relay only carries the ciphertext.`;
}
