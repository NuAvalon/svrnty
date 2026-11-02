// scripts/devin-comm-tr.ts
// The headless tr-v1 open, kept apart from devin-comm.ts (which runs main() on import) so it can be tested with real ratchet crypto.
// F1 (Flint spec v1 bcade56d, Archie #2466/#2468): R5/R6 parity with the PWA. When a contact resets and sends a NEW first frame while we
// still hold the old session, receive() fails; the SAME policy the PWA uses (session-adopt-policy.ts, imported) may then let acceptFirst
// replace the session. Only a genuine first frame can (acceptFirst rejects a continuation). No policy = no adoption, exactly as before.

import { TripleRatchet, type RatchetIdentity, type RatchetPacket, type RatchetPeer, type RatchetSnapshot } from '../src/lib/crypto/message-ratchet';

export type TrSessions = Record<string, RatchetSnapshot>;

/** The adopt question (buildAdoptFirstFrame's answer for one note). Absent on the poll / loop display paths: they have no journal. */
export type AdoptAsk = (s: { unconfirmed: boolean }) => Promise<boolean>;

export interface TrOpened {
  plaintext: string;
  next: RatchetSnapshot; // the session to save for this contact
  adopted: boolean; // true = a reset's new first frame replaced the stored session
}

/**
 * Open one tr packet from `peerFp` against the stored sessions. Changes nothing: the caller saves `next`, under its lock. null = not opened
 * (nothing to save). With a stored session, a failed receive() asks `adopt` (when given) and only on yes tries acceptFirst.
 */
export async function openTrFrame(
  sessions: TrSessions, peerFp: string, self: RatchetIdentity, peer: RatchetPeer, packet: RatchetPacket, adopt?: AdoptAsk,
): Promise<TrOpened | null> {
  const snap = sessions[peerFp];
  if (snap) {
    const s = TripleRatchet.importState(snap);
    if (!s) return null; // an unreadable row is never overwritten by acceptFirst (direct-session R3)
    const pt = await s.receive(packet);
    if (pt !== null) return { plaintext: pt, next: s.exportState(), adopted: false };
    if (!adopt || !(await adopt({ unconfirmed: snap.recvCk === null }))) return null;
    const first = await TripleRatchet.acceptFirst(self, peer, packet);
    if (!first) return null; // not a first frame (a continuation of some session): nothing replaced
    return { plaintext: first.plaintext, next: first.session.exportState(), adopted: true };
  }
  const first = await TripleRatchet.acceptFirst(self, peer, packet);
  if (!first) return null;
  return { plaintext: first.plaintext, next: first.session.exportState(), adopted: false };
}

/**
 * The adopt policy's "stored notes" from this contact: the sent_at of every decrypt-journal entry from `peerFp`, EXCLUDING `noteId` (the
 * candidate itself; the store would include it and other unopened tr notes, so it is never used). A torn line is skipped, as the poll-json
 * reader does. The caller reads the file: a read error (including no journal at all, with a session already stored) throws, and the policy
 * then refuses (fail closed). Notice entries (task / dead-note aggregates) carry the newest real sent_at of their notes: counting them only
 * makes "newer than every stored note" stricter.
 */
export function journalSentAts(journalText: string, peerFp: string, noteId: string): string[] {
  const out: string[] = [];
  for (const line of journalText.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let m: { peer_fp?: unknown; note_id?: unknown; sent_at?: unknown };
    try {
      m = JSON.parse(t);
    } catch {
      continue;
    }
    if (m.peer_fp === peerFp && m.note_id !== noteId && typeof m.sent_at === 'string') out.push(m.sent_at);
  }
  return out;
}
