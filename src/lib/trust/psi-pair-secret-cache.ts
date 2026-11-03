// src/lib/trust/psi-pair-secret-cache.ts
/**
 * A cache for the pairwise secrets the epoch-note receive path derives, one per contact. Computing one is a Diffie-Hellman; the secret is static per
 * contact, so it is worth keeping for the life of the unlocked session and no longer.
 *
 * MEMORY ONLY. It is a plain in-process Map: nothing here reads or writes any storage, and nothing in the cache is ever part of the owner's book, a
 * backup or an outbound payload. A pairwise secret lives in the unlocked session and dies with it: the cache is emptied (and the bytes it held
 * zeroed) when the session locks or the active identity changes. The factory takes the registration function for that lock hook, so this module
 * imports nothing from the store and the hook can be faked in a test.
 *
 * Keyed by contact id. Values are 32 bytes. `get` hands back a copy and `set` keeps a copy, so a caller zeroing or reusing its own buffer cannot
 * change what is cached, and the cache cannot be used to reach into a caller's memory.
 */
export const PAIR_SECRET_BYTES = 32;

export interface PairSecretCache {
  get(contactId: string): Uint8Array | undefined;
  set(contactId: string, secret: Uint8Array): void;
  /** Zero every held secret and drop them all. */
  clear(): void;
  size(): number;
}

export function createPairSecretCache(registerOnLock?: (clear: () => void) => void): PairSecretCache {
  const held = new Map<string, Uint8Array>();
  const cache: PairSecretCache = {
    get(contactId) {
      const v = held.get(contactId);
      return v === undefined ? undefined : v.slice();
    },
    set(contactId, secret) {
      if (typeof contactId !== 'string' || contactId.length === 0) throw new TypeError('psi-pair-secret-cache: contact id must be a non-empty string');
      if (!(secret instanceof Uint8Array) || secret.length !== PAIR_SECRET_BYTES) {
        throw new TypeError(`psi-pair-secret-cache: a pair secret is exactly ${PAIR_SECRET_BYTES} bytes`);
      }
      held.get(contactId)?.fill(0);
      held.set(contactId, secret.slice());
    },
    clear() {
      for (const v of held.values()) v.fill(0);
      held.clear();
    },
    size() {
      return held.size;
    },
  };
  registerOnLock?.(() => cache.clear());
  return cache;
}
