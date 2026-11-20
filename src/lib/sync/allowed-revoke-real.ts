// src/lib/sync/allowed-revoke-real.ts — #959: the REAL book for allowed-revoke.ts: the consents the owner's contacts hold NOW. Kept apart from allowed-revoke.ts (pure, injectable) the way
// beacon-key-intake-real.ts is kept apart from its composer: only this file touches storage.
import { getAllContacts, getContactBookIntegrity } from '@/lib/identity/client-store';
import { consentFromRecord } from '@/lib/contacts/share-settings-patch';
import { allowedRowShouldExist, type PeerConsent } from './allowed-sync';
import type { AllowedRevokeDeps } from './allowed-revoke';

export function realAllowedRevokeDeps(): AllowedRevokeDeps {
  return {
    // the book is whole unless the last unlock's manifest check flagged it corrupt; a failure to read the flag throws, which the drain reads as damaged
    bookComplete: async (ownerFp) => (await getContactBookIntegrity(ownerFp)) === 'ok',
    consents: async (ownerFp) => {
      const book = new Map<string, PeerConsent>();
      for (const c of await getAllContacts(ownerFp)) {
        if (!c.fingerprint) continue;
        const consent = consentFromRecord(c);
        const held = book.get(c.fingerprint);
        // two records for one fingerprint: a row is kept if EITHER allows it (never revoke a row a record still asks for)
        if (!held || (!allowedRowShouldExist(held) && allowedRowShouldExist(consent))) book.set(c.fingerprint, consent);
      }
      return book;
    },
  };
}
