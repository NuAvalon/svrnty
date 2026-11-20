// src/components/held/held-port.ts
// The hold view's LOCAL ports: the only file in the view's folder that touches the notes store or the contact book. Everything here reads or writes this device's own sealed stores; nothing here sends, fetches or
// signals anything, and nothing in it reaches a relay, a mailbox, a ratchet or a receipt (pinned in hold-view-model.test.ts).
//   - realHeldPort: one sender's held notes, and the owner's move-to-inbox / delete of one note (both counted in the store).
//   - makeHeldSectionPort(owner): who has held notes, and which fingerprints are FROZEN right now, decided by the SAME function the accept uses (isFrozenContact), so the Lenses & vault section lists exactly the
//     senders who do not have a page entry: removed or unblocked ones.
import { getAllContacts } from '@/lib/identity/client-store';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { deleteHeldNote, listHeldFrom, listHeldSenders, releaseHeldNote } from '@/lib/messaging/store';
import { isFrozenContact } from '@/lib/trust/admit-contact';
import type { HeldPort } from './hold-view-model';

export const realHeldPort: HeldPort = {
  listHeld: listHeldFrom,
  release: releaseHeldNote,
  remove: deleteHeldNote,
  nowMs: () => Date.now(),
};

export type HeldSectionPort = {
  /** Every sender that has held notes on this device, with how many (shown only inside the opened section). */
  senders(): Promise<Array<{ from_fingerprint: string; count: number }>>;
  /** The normalised fingerprints of the contacts that are frozen right now (in the book AND blocked): those keep their entry on their own page. */
  frozen(): Promise<Set<string>>;
};

export function makeHeldSectionPort(ownerFingerprint: string): HeldSectionPort {
  return {
    senders: listHeldSenders,
    frozen: async () => {
      const out = new Set<string>();
      for (const c of await getAllContacts(ownerFingerprint)) {
        const row = c as { fingerprint?: unknown; peer_fingerprint?: unknown };
        const fp = normalizeFingerprintHex(String(row.fingerprint ?? row.peer_fingerprint ?? ''));
        if (fp && isFrozenContact(c)) out.add(fp);
      }
      return out;
    },
  };
}
