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

// ISO-8601 with an explicit zone. Date.parse alone is lenient (Date.parse('5') is a date in 2001), and the replay guard is only as good as the time it compares.
const STRICT_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** A wire/stored sent_at as epoch ms, or NaN for anything that is not a strict ISO-8601 timestamp with a zone (never defaults to now). */
export function parseSentAtMs(v: unknown): number {
  return typeof v === 'string' && STRICT_ISO.test(v) ? Date.parse(v) : NaN;
}

export interface AdoptWiring {
  ownFingerprint: string;
  peerFingerprint: string;
  /** The SIGNED sent_at of the frame's note, exactly as it is on the wire. */
  sentAt: string | undefined;
  /** sent_at of every note already stored from this contact. Called only on a desync, under the session lock. */
  storedSentAts: () => Promise<string[]>;
  now: () => number;
}

/**
 * The caller's answer to the opener's "may this new first frame replace our session?". The stored notes are read ONLY when asked (a desync), and a
 * read that throws means NO (fail-closed; the frame stays a held desync). A stored sent_at that is not a strict timestamp has no usable time and is
 * skipped: it cannot help a replayer (an old frame carries its own old signed time) and one odd note from a contact must not lock that contact out
 * of healing for good.
 */
export function buildAdoptFirstFrame(w: AdoptWiring): (s: { unconfirmed: boolean }) => Promise<boolean> {
  return async ({ unconfirmed }) => {
    try {
      const times = (await w.storedSentAts()).map(parseSentAtMs).filter((t) => Number.isFinite(t));
      return mayAdoptFirstFrame({
        unconfirmed,
        ownFingerprint: w.ownFingerprint,
        peerFingerprint: w.peerFingerprint,
        sentAtMs: parseSentAtMs(w.sentAt),
        newestStoredAtMs: times.length ? Math.max(...times) : null,
        nowMs: w.now(),
      });
    } catch {
      return false;
    }
  };
}
