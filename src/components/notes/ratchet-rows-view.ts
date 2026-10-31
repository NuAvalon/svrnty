// src/components/notes/ratchet-rows-view.ts
// #720 R3/R4/R6 view-model for one contact's thread: which named rows the thread shows (Athena's ratchet-rows.ts supplies the copy, Hypatia's v0_10),
// how many held frames a reset would discard, and whether the reset action is offered. Pure: the caller passes the dead-letter rows and the
// per-contact "reset, no frame since" flag it read from the encrypted store. Nothing here reads text from a message: a row is a fixed reason,
// phase and cause token.
import { heldCountFor, type DeadLetterRow } from '@/lib/sync/dead-letter';
import { namedRow, type NamedRow, type NamedRowInput } from './ratchet-rows';

export interface RatchetRowView extends NamedRow {
  /** Stable React key: the line and hint, so identical rows collapse to ONE (the copy names no count, so none is shown). */
  key: string;
}

export interface ContactRatchetView {
  rows: RatchetRowView[];
  /** Frames from this contact kept on the relay right now: the reset dialog's count. */
  held: number;
  /** Offer the reset action: only when something from this contact failed on a ratchet reason. Never for a healthy thread. */
  canReset: boolean;
}

/** The copy input for one record, or null when the record is not a ratchet row. A holdable row with no phase reads as recorded (not "we will keep trying"). */
export function inputFor(row: DeadLetterRow, outOfStep: boolean): NamedRowInput | null {
  const phase = row.phase === 'held' ? 'held' : 'recorded';
  switch (row.reason) {
    case 'ratchet-local': return { kind: 'local', phase };
    case 'ratchet-desync': return { kind: 'desync', phase };
    case 'ratchet-unopenable': {
      const firstFrameRejected = row.cause === 'first-frame-rejected';
      return { kind: 'verdict', firstFrameRejected, outOfStep: firstFrameRejected && outOfStep };
    }
    case 'session-reset': return { kind: 'session-reset' };
    default: return null;
  }
}

/**
 * Rows newest first (by first_seen), identical lines collapsed. `outOfStep` is the per-contact reset flag; it changes the wording of a
 * first-frame-rejected verdict row only (copy v0_10), never any other row.
 */
export function ratchetViewFor(rows: ReadonlyArray<DeadLetterRow>, peerFp: string, contactName: string, outOfStep: boolean): ContactRatchetView {
  const want = peerFp.toLowerCase();
  const mine = rows
    .filter((r) => typeof r.fp === 'string' && r.fp.toLowerCase() === want)
    .sort((a, b) => Date.parse(b.first_seen) - Date.parse(a.first_seen) || (a.envelope_id < b.envelope_id ? -1 : 1));
  const out: RatchetRowView[] = [];
  const seen = new Set<string>();
  for (const r of mine) {
    const input = inputFor(r, outOfStep);
    if (!input) continue;
    const named = namedRow(contactName, input);
    const key = `${named.line}\n${named.hint ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ...named, key });
  }
  const canReset = mine.some((r) => r.reason === 'ratchet-local' || r.reason === 'ratchet-desync' || r.reason === 'ratchet-unopenable');
  return { rows: out, held: heldCountFor(rows, want), canReset };
}
