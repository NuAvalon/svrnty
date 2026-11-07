// src/lib/sync/epoch-seam.ts
/**
 * The epoch-note seam for the consume pipeline, built from injected parts: open the sealed package, then hand the plaintext to the ruled receive logic
 * (psi-epoch-receive) with the book, the pairwise secret, the clock and the store write supplied here. Nothing in this file touches storage or the
 * network directly; live-book-poll supplies the real parts.
 *
 * The pairwise secret with a contact is derived from OUR signing seed and THEIR signing key, and that key is read from the book record the lookup
 * returned (signPubForContact binds it to the contact's fingerprint). The seed is fetched only on a cache miss, copied, and zeroed straight after the
 * derivation. A derivation that fails for any reason (no seed, a key that is not a usable point) is "cannot verify", which the receive logic records
 * as unverified and never adopts.
 *
 * It never names the epoch field: the held epoch record reaches the decision as an argument of the store's writer.
 */
import type { ContactRecord } from '@/lib/identity/client-store';
import { admitContact } from '@/lib/trust/admit-contact';
import { deriveSharedSecret } from '@/lib/crypto/mutual-trust';
import { signPubForContact } from '@/lib/identity/raw-sign-public';
import { receiveEpochNote, type EpochReceiveDeps } from '@/lib/trust/psi-epoch-receive';
import type { PairSecretCache } from '@/lib/trust/psi-pair-secret-cache';
import type { EpochNoteSeam } from './consume-mailbox';

export interface EpochSeamDeps {
  ownerFp: string;
  /** F1. Only exactly true switches the receive path on. */
  receiveOn: boolean;
  /** Open a sealed package to its plaintext bytes (the reviewed opener), or null if it is not one that opens here. */
  openPackage: (blob: string) => Promise<Uint8Array | null>;
  /** The local book (a public reader: it returns the record without the epoch field). */
  getContactByFingerprint: (ownerFp: string, fp: string) => Promise<ContactRecord | null>;
  /** A FRESH copy of our 32-byte signing seed, or null when it cannot be had (locked, cycle ended). The seam zeroes it after use. */
  ownerSeed: () => Promise<Uint8Array | null>;
  cache: PairSecretCache;
  nowMinutes: () => number;
  /** The store's writer of the epoch record. */
  adopt: EpochReceiveDeps['adopt'];
}

export function buildEpochSeam(d: EpochSeamDeps): EpochNoteSeam {
  // The record each lookup returned, by contact id, for the life of this seam (one poll). The secret is derived from THIS record, never from a second
  // read that could see a key rotated in between.
  const seen = new Map<string, ContactRecord>();
  return {
    open: d.openPackage,
    receive: (plain) =>
      receiveEpochNote(plain, {
        receiveOn: d.receiveOn,
        ownerFp: d.ownerFp,
        findContact: async (fp) => {
          const rec = await d.getContactByFingerprint(d.ownerFp, fp);
          if (!rec) return null;
          seen.set(rec.id, rec);
          return { id: rec.id, fingerprint: rec.fingerprint, blocked: !admitContact(rec) };
        },
        pairSecretFor: async (contactId) => {
          const rec = seen.get(contactId);
          if (!rec) return null;
          const peerSignPub = await signPubForContact(rec);
          if (!peerSignPub) return null;
          const cached = d.cache.get(contactId, peerSignPub);
          if (cached) return cached;
          let seed: Uint8Array | null = null;
          try {
            seed = await d.ownerSeed();
            if (!seed) return null;
            const secret = deriveSharedSecret(seed, peerSignPub);
            d.cache.set(contactId, peerSignPub, secret);
            return secret;
          } catch {
            return null;
          } finally {
            seed?.fill(0);
          }
        },
        nowMinutes: d.nowMinutes,
        adopt: d.adopt,
      }),
  };
}
