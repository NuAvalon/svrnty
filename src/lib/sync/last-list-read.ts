// src/lib/sync/last-list-read.ts
// The LAST read of the satellite's allowed list for each owner, kept IN MEMORY only, so the owner's "what the relay holds" panel can show what the revoke check last saw (and when) without making a request of its own.
//   - Every status is kept, not just 'ok': the LAST read wins. An 'unknown' after an 'ok' means the panel says it could not check; it never shows an older list as if it were current.
//   - Memory only: no storage, no log line, no network. Forgotten on lock, logout and identity switch (below). It is the list the relay gave (fingerprints, up to MAX_LISTED), held for the life of the page; resetLastListRead() forgets it.
//   - recordListRead returns its argument UNCHANGED, so wrapping the drain's list call with it cannot change what the drain sees.
import type { AllowedListResult } from './allowed-sync';
import { onSessionLock } from '@/lib/identity/client-store';

export interface LastListRead { result: AllowedListResult; at: number }

const last = new Map<string, LastListRead>();

export function recordListRead(ownerFp: string, result: AllowedListResult, at: number = Date.now()): AllowedListResult {
  last.set(ownerFp, { result, at });
  return result;
}

export function lastListRead(ownerFp: string): LastListRead | undefined {
  return last.get(ownerFp);
}

export function resetLastListRead(): void {
  last.clear();
}

// Cleared on LOCK, on LOGOUT and on an IDENTITY SWITCH: all three go through the session-lock hooks (lockSession and setActiveFingerprint, the one switch chokepoint that restore and import also use). A locked device shows nothing of the owner's graph, so the panel can only say it could not check. Registered once, at module load: the hook list is append-only.
onSessionLock(resetLastListRead);
