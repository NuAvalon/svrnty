/**
 * Per-method relay — glass only.
 *
 * Records which relay host a method intends to use. Move/switch-relay
 * resolution and propagation are Apollo/Athena (`routing.update`). This
 * module CALLS that seam when the fleet registers it; it never implements
 * routing itself.
 */

import { SVRNTY_DOMAIN } from '@/lib/config/domain';
import { updateOwnerMethod, type OwnerCardBag } from '@/components/identity/owner-card';

export function defaultRelayHost(): string {
  return SVRNTY_DOMAIN;
}

/**
 * https host only (I-10a). Rejects javascript:/data:/http:.
 * Accepts a bare host or an https URL; stores the host.
 */
export function normalizeRelayHost(input: string): string | null {
  const raw = (input || '').trim();
  if (!raw) return null;
  if (/^(javascript|data|file|blob):/i.test(raw)) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `https://${raw}`;
  try {
    const u = new URL(candidate);
    if (u.protocol !== 'https:') return null;
    const host = u.host.trim().toLowerCase();
    if (!host || host.includes(' ')) return null;
    return host;
  } catch {
    return null;
  }
}

export type MethodRelayMoveResult =
  | { ok: true; host: string; delivered: boolean }
  | { ok: false; reason: 'invalid-host' };

/** Fleet seam — register when routing.update lands. Glass never implements it. */
export type TeamMethodRelayMove = (args: {
  methodId: string;
  host: string;
}) => Promise<{ ok: true } | { ok: false; reason: string }>;

let teamMove: TeamMethodRelayMove | null = null;

export function registerTeamMethodRelayMove(fn: TeamMethodRelayMove | null): void {
  teamMove = fn;
}

export function teamMethodRelayMoveRegistered(): boolean {
  return teamMove !== null;
}

/**
 * Persist the intended relay host on the local owner-card bag, then call
 * the fleet move if registered. `delivered: false` means the host is saved
 * here only — delivery still uses the current relay.
 */
export async function requestMethodRelayMove(
  bag: OwnerCardBag,
  methodId: string,
  rawHost: string,
): Promise<{ result: MethodRelayMoveResult; bag: OwnerCardBag }> {
  const host = normalizeRelayHost(rawHost);
  if (!host) return { result: { ok: false, reason: 'invalid-host' }, bag };
  const next = updateOwnerMethod(bag, methodId, { relay: host });
  if (!teamMove) {
    return { result: { ok: true, host, delivered: false }, bag: next };
  }
  const wired = await teamMove({ methodId, host });
  return { result: { ok: true, host, delivered: wired.ok }, bag: next };
}
