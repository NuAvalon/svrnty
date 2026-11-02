// N10 cross-tab hardening (Flint #178309): the notes store is tab-local module state that putNote writes through.
// Before an inbound note is accepted, the store must be open FOR THIS owner — not merely unlocked. Throwing (not
// returning/omitting the seam) is load-bearing: consumeOne maps a throw to RETRYABLE, so the note waits in the
// mailbox; a missing seam would let the blob fall through to the contact-update path and be ack-DELETED.
export function assertNotesStoreOpenFor(openOwner: string | null, owner: string): void {
  if (openOwner === null || openOwner !== owner) {
    throw new Error('notes store is not open for this owner — note held for retry');
  }
}
