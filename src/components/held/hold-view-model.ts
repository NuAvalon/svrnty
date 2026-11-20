// src/components/held/hold-view-model.ts
// What the hold view does that is not drawing: the port it works through, the two loops over ALL notes, and the lines under each note. Pure and React-free, so every rule here is run in a unit test with a fake
// port; the screen (HeldMessagesView.tsx) only draws it.
//
// THE VIEW SENDS NOTHING. This file and the screen import no messaging store, no transport, no relay, no mailbox, no ratchet and no receipt module (pinned by hold-view-model.test.ts): everything the view does
// to a note goes through the four operations of the HeldPort, which the app wires to the local store (held-port.ts) and which never touch the network.
//
// Run: npx tsx --test src/components/held/hold-view-model.test.ts
import { heldAtMs, heldExpiry, holdLimits, type HeldMoveResult } from '@/lib/messaging/held-note';
import type { NoteRecord } from '@/lib/messaging/types';
import { holdViewArrived, holdViewExpiring, holdViewSentByTheirClock } from './hold-view-copy';

/** The four things the view may do. Local to this device; none of them sends anything. */
export type HeldPort = {
  /** The held notes from one sender, newest first. */
  listHeld(fingerprint: string): Promise<NoteRecord[]>;
  /** Move one held note to the inbox (counted). */
  release(noteId: string): Promise<HeldMoveResult>;
  /** Delete one held note (counted). */
  remove(noteId: string): Promise<HeldMoveResult>;
  /** The owner's clock. */
  nowMs(): number;
};

/** What a loop over ALL notes ended with: how many it moved or deleted, or that it stopped, with how many held notes from this person are STILL there (re-counted, never inferred). */
export type BulkResult = { ok: true; n: number } | { ok: false; stillHere: number };

/**
 * Run one operation over a list of note ids, one at a time, and stop at the first note that could not be handled. 'done' counts; 'gone' (a sweep got there first) and 'not-held' (it already left the hold) are not
 * failures and not counted; 'unreadable' and 'lost-race' are failures. After a failure the number still held is read AGAIN from the store: a loop can stop part-way, so the screen must not guess it. A port
 * that throws (a locked store) is a failure like any other. If even the re-count fails, that error is the caller's (the screen shows its load failure, never a made-up number).
 */
async function runOverAll(port: HeldPort, fingerprint: string, ids: string[], op: (id: string) => Promise<HeldMoveResult>): Promise<BulkResult> {
  let n = 0;
  for (const id of ids) {
    let res: HeldMoveResult;
    try {
      res = await op(id);
    } catch {
      res = 'lost-race';
    }
    if (res === 'done') n++;
    else if (res === 'unreadable' || res === 'lost-race') return { ok: false, stillHere: (await port.listHeld(fingerprint)).length };
  }
  return { ok: true, n };
}

export const moveAllHeld = (port: HeldPort, fingerprint: string, ids: string[]): Promise<BulkResult> => runOverAll(port, fingerprint, ids, (id) => port.release(id));
export const deleteAllHeld = (port: HeldPort, fingerprint: string, ids: string[]): Promise<BulkResult> => runOverAll(port, fingerprint, ids, (id) => port.remove(id));

/** The lines under one note's body: when it arrived on this device, the sender's own time labelled as theirs, and the expiring mark when the sweep has marked it. Each is null when there is nothing true to say. */
export type NoteLines = { arrived: string | null; theirs: string | null; expiring: string | null };

const when = (ms: number): string | null => (Number.isFinite(ms) ? new Date(ms).toLocaleString() : null);

export function noteLines(note: NoteRecord, nowMs: number): NoteLines {
  const heldAt = heldAtMs(note) ?? Number.NaN;
  const sentAt = Date.parse(note.sent_at);
  const e = heldExpiry(note, nowMs, holdLimits().limitDays, holdLimits().graceDays);
  const date = e.expiring ? new Date(e.removableAfterMs).toLocaleDateString() : null;
  return {
    arrived: when(heldAt) === null ? null : holdViewArrived(when(heldAt) as string),
    theirs: when(sentAt) === null ? null : holdViewSentByTheirClock(when(sentAt) as string),
    expiring: date === null ? null : holdViewExpiring(date),
  };
}

/** A short, technical label for one sender in the list of senders (a removed or unblocked sender has no page to carry their name): the first eight hex digits of the fingerprint. An identifier, not copy. */
export const senderTag = (fingerprint: string): string => fingerprint.slice(0, 8).toLowerCase();
