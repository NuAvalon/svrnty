// src/lib/messaging/session-adopt-policy.ts
// #720 R5 + R6 (Flint reset-semantics v1): may a peer's NEW first frame replace the ratchet session we hold with them?
// Pure. The caller (the note receive seam) supplies the facts it alone knows: the note's SIGNED sent_at, the newest sent_at already stored from
// that contact, both fingerprints; the opener supplies `unconfirmed`.
//
//   R5b REPLAY GUARD  the signed sent_at must be newer than EVERY note already stored from that contact; if none is stored, within the relay
//                     window (7 days) of now. A third party re-depositing an old sealed first frame from this contact (whose note may have aged
//                     out of the store) must not rewind the session to its original state. A third party cannot change the signed sent_at.
//   R6 TIE-BREAK      a session WE initiated that has received nothing from the peer yet is 'unconfirmed'. If the peer's first frame arrives while ours
//                     is unconfirmed, the session initiated by the LOWER canonical fingerprint (lowercase hex compare) wins: the higher side adopts
//                     the peer's, the lower side refuses (that one frame is recorded and acked, named row). A CONFIRMED session has no tie-break.
// Authentication is NOT decided here: this runs only after the note's sender signature verified and the sender is admitted (N-R5c).

export const RELAY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

export interface AdoptFacts {
  unconfirmed: boolean;
  ownFingerprint: string;
  peerFingerprint: string;
  /** The note's SIGNED sent_at (ms). Not finite -> refuse. */
  sentAtMs: number;
  /** The newest sent_at (ms) among notes already stored from this contact, or null when none is stored. */
  newestStoredAtMs: number | null;
  nowMs: number;
}

export function mayAdoptFirstFrame(f: AdoptFacts): boolean {
  if (!Number.isFinite(f.sentAtMs) || !Number.isFinite(f.nowMs)) return false;
  // R5b replay guard
  if (f.newestStoredAtMs !== null) {
    if (!Number.isFinite(f.newestStoredAtMs) || !(f.sentAtMs > f.newestStoredAtMs)) return false;
  } else if (f.nowMs - f.sentAtMs > RELAY_WINDOW_MS) {
    return false;
  }
  // R6 tie-break (only while our own session is still unconfirmed)
  if (f.unconfirmed && f.ownFingerprint.toLowerCase() < f.peerFingerprint.toLowerCase()) return false; // we are the lower fp: ours wins
  return true;
}
