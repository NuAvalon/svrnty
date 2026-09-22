// src/sw/gd-warn.ts
// Node Zero G-D — the §3 WARN floor (Flint verdict §3 / #141762). The invariants this module enforces:
//
//  • WARN, NEVER BRICK: a verify failure surfaces a loud, actionable warning to the UI; it never locks the app.
//  • ONE-TIME "PROCEED ANYWAY" ≠ RE-PIN: proceeding runs the diverged bundle for THIS session only. It is
//    session-scoped (never persisted as trusted) and the pin is marked diverged (persistent, gd-pin-store),
//    so the warning RE-FIRES on the next load. It NEVER silently re-pins the attacker lineage. Adopting a fork
//    is a SEPARATE, deliberate WebAuthn-PRF step-up act (out of the launch scope; a seam, not this path).
//  • EXPORT IS PUBLISHER-INDEPENDENT (anti-hostage): the export/backup flow must serve regardless of verify or
//    diverged state — a compromised publisher must never be able to hold the user's own data hostage. Proceeding
//    does NOT make the export "safe" (the diverged code could tamper it) — the WARN says so plainly; but it is
//    never BLOCKED.
//
// The verify-flow (gd-sw / fetch handler) drives this: on mismatch it calls broadcastWarn + markDiverged and,
// unless proceed was granted this session, serves last-known-good; export paths bypass the gate entirely.

export interface WarnDetail {
  kind: 'verify-fail' | 'asset-mismatch' | 'diverged-refire';
  reason: string;
  path?: string; // the offending asset, for asset-mismatch
  publisherFpHex?: string; // the pinned lineage, for the UI
}

/** Loud, actionable WARN to every client (controlled + uncontrolled). The UI renders the override ceremony. */
export async function broadcastWarn(detail: WarnDetail): Promise<void> {
  try {
    // @ts-expect-error self is the ServiceWorkerGlobalScope at runtime
    const clients: Array<{ postMessage: (m: unknown) => void }> = await self.clients.matchAll({
      includeUncontrolled: true,
      type: 'window',
    });
    for (const c of clients) {
      c.postMessage({
        type: 'NODEZERO_WARN',
        // honest wording: proceeding runs UNVERIFIED code; it does not make it safe.
        message: 'This app could not be verified against its publisher. Proceeding runs unverified code.',
        detail,
      });
    }
  } catch {
    // never let a WARN-delivery failure brick the SW; the diverged mark + re-fire still stand.
  }
}

// Session-scoped one-time "proceed anyway". NOT persisted — a diverged run stays marked (gd-pin-store) and the
// warning re-fires next load. Cleared when the SW restarts (a new session = a fresh warning).
let _proceedThisSession = false;
export function grantOneTimeProceed(): void {
  _proceedThisSession = true;
}
export function proceedGrantedThisSession(): boolean {
  return _proceedThisSession;
}

// EXPORT-independence (anti-hostage). The exact export routes are app-specific; they are supplied at SW init
// (never guessed) so this invariant can't silently miss a route or over-broadly bypass verification.
let _exportPathPrefixes: string[] = [];
export function configureExportPaths(prefixes: string[]): void {
  _exportPathPrefixes = prefixes.slice();
}
/** True for a request that MUST serve regardless of verify/diverged state (the user's own data export). */
export function isExportPath(url: URL): boolean {
  return _exportPathPrefixes.some((p) => url.pathname === p || url.pathname.startsWith(p.endsWith('/') ? p : p + '/'));
}
