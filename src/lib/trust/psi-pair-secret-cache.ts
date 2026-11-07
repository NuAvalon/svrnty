// src/lib/trust/psi-pair-secret-cache.ts
/**
 * A cache for the pairwise secrets the epoch-note receive path derives, one per contact. Computing one is a Diffie-Hellman; the secret is static per
 * contact, so it is worth keeping for the life of the unlocked session and no longer.
 *
 * MEMORY ONLY. It is a plain in-process Map: nothing here reads or writes any storage, and nothing in the cache is ever part of the owner's book, a
 * backup or an outbound payload. A pairwise secret lives in the unlocked session and dies with it: the cache is emptied (and the bytes it held
 * zeroed) when the lock hook it is registered with fires. The factory takes the registration function for that lock hook, so this module
 * imports nothing from the store and the hook can be faked in a test. The hook is REQUIRED: a cache that is never told to clear would quietly break
 * the memory-only promise above. The store fires its lock hook from lockSession and from setActiveFingerprint, so registering this clear with it
 * empties the cache on a lock AND on an active-identity switch; this module only guarantees that it clears when the hook it was given fires, and the
 * code that registers it carries the test for the real events.
 *
 * Keyed by contact id AND the peer's signing key the secret was derived from. A contact id is a random identifier that survives a key rotation (the
 * contact keeps its id and accepts a new validly-bound public key), so an id-only key would keep serving a secret derived from the rotated-away key.
 * With the peer key in the key, a rotation is a cache miss by construction and there is no invalidation hook to forget; the old slot just stays
 * isolated until the cache is cleared. The key is held in memory only, like the secret. Values are 32 bytes. `get` hands back a copy and `set` keeps a copy, so a caller zeroing or reusing its own buffer cannot
 * change what is cached, and the cache cannot be used to reach into a caller's memory.
 */
export const PAIR_SECRET_BYTES = 32;

export const PEER_KEY_BYTES = 32;

export interface PairSecretCache {
  get(contactId: string, peerSignPub: Uint8Array): Uint8Array | undefined;
  set(contactId: string, peerSignPub: Uint8Array, secret: Uint8Array): void;
  /** Zero every held secret and drop them all. */
  clear(): void;
  size(): number;
}

export function createPairSecretCache(registerOnLock: (clear: () => void) => void): PairSecretCache {
  if (typeof registerOnLock !== 'function') throw new TypeError('psi-pair-secret-cache: a lock hook is required, or the cache would never clear');
  const held = new Map<string, Uint8Array>();
  const slot = (contactId: string, peerSignPub: Uint8Array): string => {
    if (typeof contactId !== 'string' || contactId.length === 0) throw new TypeError('psi-pair-secret-cache: contact id must be a non-empty string');
    if (!(peerSignPub instanceof Uint8Array) || peerSignPub.length !== PEER_KEY_BYTES) {
      throw new TypeError(`psi-pair-secret-cache: a peer signing key is exactly ${PEER_KEY_BYTES} bytes`);
    }
    let hex = '';
    for (const b of peerSignPub) hex += b.toString(16).padStart(2, '0');
    return `${contactId}\u0000${hex}`;
  };
  const cache: PairSecretCache = {
    get(contactId, peerSignPub) {
      const v = held.get(slot(contactId, peerSignPub));
      return v === undefined ? undefined : v.slice();
    },
    set(contactId, peerSignPub, secret) {
      const key = slot(contactId, peerSignPub);
      if (!(secret instanceof Uint8Array) || secret.length !== PAIR_SECRET_BYTES) {
        throw new TypeError(`psi-pair-secret-cache: a pair secret is exactly ${PAIR_SECRET_BYTES} bytes`);
      }
      held.get(key)?.fill(0);
      held.set(key, secret.slice());
    },
    clear() {
      for (const v of held.values()) v.fill(0);
      held.clear();
    },
    size() {
      return held.size;
    },
  };
  registerOnLock(() => cache.clear());
  return cache;
}
