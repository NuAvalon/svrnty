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
import { UnlockCycleEnded } from '@/lib/crypto/unlock-cycle';
import { extractRawSign } from '@/lib/identity/raw-sign';
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
  // The record each lookup returned travels with the contact it describes (EpochContact.ref), so the secret for a note is derived from the record THAT
  // note's decision saw: not from a second read, and not from anything shared with another note in the same poll (two notes from one contact with a
  // key rotation between them each keep their own record).
  return {
    open: d.openPackage,
    receive: (plain) =>
      receiveEpochNote<ContactRecord>(plain, {
        receiveOn: d.receiveOn,
        ownerFp: d.ownerFp,
        findContact: async (fp) => {
          const rec = await d.getContactByFingerprint(d.ownerFp, fp);
          if (!rec) return null;
          return { id: rec.id, fingerprint: rec.fingerprint, blocked: !admitContact(rec), ref: rec };
        },
        pairSecretFor: async (contact) => {
          const rec = contact.ref;
          const contactId = contact.id;
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

/**
 * Open a sealed package to its plaintext, or say it is not one that opens here. "Not an envelope" is null. A package that does not open with our keys
 * (a wrong key, a corrupt body) is also null, exactly as every other opener treats it: it is not ours to read, and the contact-update path then deals
 * with it as it always has. The ONE exception is a cycle that has ended (the session locked or switched): then we cannot tell whether this is ours,
 * so the error is rethrown and the consume pipeline leaves the envelope on the relay for a later poll. It must never fall through to the
 * contact-update path, which is the thing this seam exists to keep an epoch package away from. (Rethrowing EVERY error would make one malformed
 * package a poison pill, retried and never acknowledged on every poll.)
 */
export async function openEpochPackage(
  blob: string,
  parts: {
    asPackage: (blob: string) => unknown | null;
    open: (pkg: never) => Promise<Uint8Array | null>;
  },
): Promise<Uint8Array | null> {
  const pkg = parts.asPackage(blob);
  if (!pkg) return null;
  try {
    return await parts.open(pkg as never);
  } catch (e) {
    if (e instanceof UnlockCycleEnded) throw e;
    return null;
  }
}

/**
 * The seam is installed ONLY when the receive switch is on. With it off nothing is built and nothing is supplied, so the poll path is exactly what it
 * is without this feature: no extra open per package, no new acknowledgement behaviour.
 */
export function installEpochSeam(receiveOn: boolean, build: () => EpochNoteSeam): EpochNoteSeam | undefined {
  return receiveOn === true ? build() : undefined;
}

/**
 * The seam's source of our signing seed: a COPY of the seed of this cycle's one unlocked key, or null when the cycle is locked or has ended (cannot
 * verify). It is a copy because extractRawSign hands back the key's OWN buffer, which the rest of the cycle still signs with: the seam zeroes the copy and
 * the cycle's key stays usable (epoch-seed-ownership.test.ts shows both halves).
 */
export function ownerSeedFromCycle(cycle: { key(): Promise<unknown> }): () => Promise<Uint8Array | null> {
  return async () => {
    try {
      return extractRawSign(await cycle.key()).seed.slice();
    } catch {
      return null; // locked, or the cycle ended: cannot verify
    }
  };
}
