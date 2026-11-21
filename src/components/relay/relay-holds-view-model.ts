// src/components/relay/relay-holds-view-model.ts
// WHAT THE PANEL SAYS, in order, for each state. Pure: the component only renders these lines. Every sentence is the copy owner's (relay-holds-copy.ts); nothing here words anything.
//
//   unknown / no-list / book-damaged : ONE line each, no rows, no "Checked", no by-design line.
//   ok : the over-listed line, the under-listed line (its ROWS are offered for a deliberate Repair), the key-less line (a fact, no Repair; shown even when the diff is otherwise empty), then, ONLY with a read time:
//        the nothing-differs line (only when over, under AND key-less are all 0, and always immediately before the "Checked ..." line that dates it), the "Checked ..." line; then the by-design line once.
// No fingerprint is ever in a line: an over-listed person is a count, an under-listed one is a contact the owner already has, shown by name.
import * as copy from './relay-holds-copy';
import { showsAllMatch, type PanelModel, type UnderRow } from './relay-holds-model';
import type { RepairOutcome } from './relay-holds-repair';

export type LineId = 'unknown' | 'no-list' | 'book-damaged' | 'over' | 'under' | 'nokey' | 'allmatch' | 'checked' | 'bydesign';
export interface ViewLine { id: LineId; text: string }

export function viewLines(model: PanelModel, at: number | undefined, nowMs: number): { lines: ViewLine[]; rows: UnderRow[] } {
  if (model.kind === 'unknown') return { lines: [{ id: 'unknown', text: copy.RELAY_COULD_NOT_CHECK }], rows: [] };
  if (model.kind === 'no-list') return { lines: [{ id: 'no-list', text: copy.RELAY_NO_LIST }], rows: [] };
  if (model.kind === 'book-damaged') return { lines: [{ id: 'book-damaged', text: copy.RELAY_BOOK_DAMAGED }], rows: [] };
  const lines: ViewLine[] = [];
  const over = copy.overListedLine(model.overCount);
  if (over) lines.push({ id: 'over', text: over });
  const under = copy.underListedLine(model.under.length);
  if (under) lines.push({ id: 'under', text: under });
  const noKey = copy.noKeyLine(model.noKeyCount);
  if (noKey) lines.push({ id: 'nokey', text: noKey });
  if (at !== undefined) {
    if (showsAllMatch(model)) lines.push({ id: 'allmatch', text: copy.RELAY_ALL_MATCH });
    lines.push({ id: 'checked', text: copy.checkedLine(nowMs - at) });
  }
  lines.push({ id: 'bydesign', text: copy.RELAY_BY_DESIGN });
  return { lines, rows: model.under };
}

/** The line under a Repair row after a press: the contact's real name fills it (a nameless one reads "this person" mid-sentence). A press that was refused or ignored says nothing. */
export function repairLine(outcome: RepairOutcome, name: string | null): string | null {
  switch (outcome.kind) {
    case 'repaired': return copy.repairedLine(name);
    case 'failed': return copy.repairFailedLine(name);
    case 'gone': return copy.repairGoneLine(name);
    case 'unreadable': return copy.RELAY_COULD_NOT_CHECK;
    default: return null;
  }
}
