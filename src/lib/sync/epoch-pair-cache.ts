// src/lib/sync/epoch-pair-cache.ts
/**
 * The one pairwise-secret cache for the epoch-note receive path: memory only, and emptied by the store's lock hook, which the store fires from
 * lockSession and from setActiveFingerprint (the identity switch). A pairwise secret lives in the unlocked session and dies with it.
 */
import { onSessionLock } from '@/lib/identity/client-store';
import { createPairSecretCache } from '@/lib/trust/psi-pair-secret-cache';

export const epochPairSecretCache = createPairSecretCache(onSessionLock);
