// src/lib/messaging/ratchet-open.ts
// #720 contract v5.3 (Flint #2052): the ratchet open, with every failure TYPED as 'local' (this device) or 'verdict' (the frame / the
// sender's card). The old path returned null for both, so the interim "record + ack" would have acked away a real contact's message on a
// transient LOCAL fault (our key not unlocked, an unreadable session row) with advice ("ask them to resend") that cannot help.
//
// The rule that keeps it honest: UNKNOWN IS LOCAL. Only a cause positively identified as the frame's fault is a verdict. A throw anywhere
// in the chain is local too (the old catch-all swallowed it into a plain null). The loaders are injected so every branch is testable.

import type { RatchetIdentity, RatchetPeer } from '@/lib/crypto/message-ratchet';
import type { OpenFailure, StagedOpen } from './direct-session';

export interface RatchetOpenLoaders {
  /** OUR ratchet identity. Every null here concerns our own keys (missing key row, missing/unparseable PQ bundle, an unlock that failed), so it is LOCAL. */
  loadSelf: () => Promise<RatchetIdentity | null>;
  /** The sender is ADMITTED, so their record must exist; false means it vanished between admit and now (unidentified => LOCAL). */
  contactExists: () => Promise<boolean>;
  /** The peer's ratchet card. Null for an ADMITTED contact whose card carries no usable PQ keys: a property of the contact, a VERDICT. */
  loadPeer: () => Promise<RatchetPeer | null>;
  open: (self: RatchetIdentity, peer: RatchetPeer) => Promise<StagedOpen | OpenFailure>;
}

const local = (cause: string): OpenFailure => ({ failed: true, kind: 'local', cause });
const verdict = (cause: string): OpenFailure => ({ failed: true, kind: 'verdict', cause });

export async function openRatchetClassified(l: RatchetOpenLoaders): Promise<StagedOpen | OpenFailure> {
  try {
    const self = await l.loadSelf();
    if (!self) return local('own-ratchet-identity-unavailable');
    if (!(await l.contactExists())) return local('contact-missing-after-admit');
    const peer = await l.loadPeer();
    if (!peer) return verdict('peer-card-has-no-pq-keys');
    return await l.open(self, peer);
  } catch {
    return local('open-threw'); // the old catch-all swallowed this into null; the cause is unknown, so it is this device's until proven otherwise
  }
}
