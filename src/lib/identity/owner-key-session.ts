// src/lib/identity/owner-key-session.ts — the SYNCHRONOUS copy of the owner's alias map, for callers that cannot await (task: owner-side step B).
/**
 * DARK: nothing imports this yet. Several owner-keyed reads are synchronous (localStorage users, readEnrollPreference), so the resolver must
 * not need an await. The alias map is persisted as a plaintext row in IndexedDB settings (device-wide: only this device's OWN fingerprints,
 * already plaintext as object-store keyPaths); this module holds a copy in memory with THREE states (Flint #7362, #7376):
 *   - NOT LOADED: `ownerKey` THROWS ('not-loaded'). It never returns its argument. A read that runs before the map is loaded (the notes DB open
 *     at unlock, the biometric lookup) would otherwise silently use the operational fingerprint, open `svrnty-notes-<new fp>` (an empty DB) and
 *     split new notes off from the history.
 *   - LOADED, NO ALIASES: `ownerKey` passes the argument through unchanged (today's bytes for an owner who never rotated).
 *   - LOADED, WITH ALIASES: `ownerKey` resolves an operational fingerprint to the durable id.
 * WHO SETS IT (ruling A): client-store's ONE DB-open path loads it from the persisted row, and client-store refreshes it from the COMMITTED row
 * right after a rotation's transaction commits. Nothing else calls `loadOwnerAliases` (a test names the allowed importer by exact path). It is
 * NOT cleared on lock: the row is already plaintext, clearing protects nothing, and since it reloads only at DB open, clearing it would break
 * the identity-picker flow (lockSession, setActiveFingerprint, initSessionKey). `clearOwnerAliases` exists for tests and for a failed refresh.
 * There is no getter for the map and no setter for one entry. A malformed row, or any failure while loading, leaves the state NOT LOADED: it is
 * surfaced (the call throws), never repaired by falling back to the operational fingerprint.
 */
import { ownerStoreKey, withOwnerAlias, OwnerKeyError, type OwnerAliases } from './owner-key';

let aliases: OwnerAliases | null = null;

/** The storage key for the active owner. Throws OwnerKeyError('not-loaded') until the unlock path has loaded the persisted alias map. */
export function ownerKey(fingerprint: string): string {
  if (aliases === null) throw new OwnerKeyError('not-loaded');
  return ownerStoreKey(fingerprint, aliases);
}

export function isOwnerKeyLoaded(): boolean {
  return aliases !== null;
}

/**
 * client-store ONLY (the DB-open path and the post-commit refresh). `entries` are the persisted [operational fingerprint, durable id] pairs. Replaces the copy atomically; any malformed pair,
 * conflict or chain throws and leaves the state NOT LOADED. The pairs are copied: changing `entries` afterwards changes nothing.
 */
export function loadOwnerAliases(entries: ReadonlyArray<readonly [string, string]>): void {
  aliases = null; // a failed load must not leave an older map in place
  if (!Array.isArray(entries)) throw new OwnerKeyError('bad-alias');
  let next: OwnerAliases | undefined;
  for (const pair of entries) {
    if (!Array.isArray(pair) || pair.length !== 2) throw new OwnerKeyError('bad-alias');
    next = withOwnerAlias(next, pair[0], pair[1]);
  }
  aliases = next ?? new Map<string, string>();
}

/** Forget the copy (tests; a failed refresh). Every owner-keyed read throws again until the next load. NOT called on lock (ruling A). */
export function clearOwnerAliases(): void {
  aliases = null;
}
