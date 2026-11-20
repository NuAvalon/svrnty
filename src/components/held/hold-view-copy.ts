// src/components/held/hold-view-copy.ts
// The words on the hold view (the owner's own screen of held notes), copy ledger rows 335a-335i4 and 316a. Reviewed copy: do not reword it here; a change needs the copy owner's new row and new hash.
// Plain ASCII, straight apostrophes. Each template is pinned by length and sha256 prefix in hold-view-copy.test.ts. Placeholders are written {like_this} and filled by fill() below.
//   - The entry label carries NO count and no digit, ever (335a). The view is the only place numbers appear, and only after the owner opened it.
//   - Nothing here says they will not know, silently, secretly, safely stored, forever, or private as a promise (335k).
//   - A failure line for ONE note says nothing was changed (one note's write is one compare-and-swap); a failure line for ALL says how many are still here, re-counted, never "nothing was changed" (335i3, 335i4).
//   - No copy for a reply or for the evidence export: neither is in this view (335l).
// Run: npx tsx --test src/components/held/hold-view-copy.test.ts

/** Row 335a / 335b1 (13 chars, sha256 prefix 7ddea045e35a1c25): the entry label and the view's title. */
export const HOLD_VIEW_TITLE = 'Held messages';
export const HOLD_VIEW_ENTRY = HOLD_VIEW_TITLE;
/** Row 335b2 (100, 90f3a9deed15742a): the intro. {name} is the contact's name, or "this person". True only while the view, moving and deleting send nothing (the zero-request browser pin). */
export const HOLD_VIEW_INTRO = 'These arrived while you had {name} frozen. Opening, moving or deleting them sends nothing to {name}.';
/** Row 335c (102, 04860d0eb76f2b23): the age limit, shown beside the cap line. Left out when the limit is 0 (nothing is removed). */
export const HOLD_VIEW_AGE_LINE = 'Notes held here longer than {days} days are marked expiring, then removed at least {grace} days later.';
/** Row 316a (165, 01723c8a6dc21b7a): the cap line, shown beside the age line. */
export const HOLD_VIEW_CAP_LINE = "We keep up to {cap} notes from each person you've frozen. After that, new notes from them aren't kept, and they stop getting delivery receipts, so they could notice.";
/** Row 335d (17, 09361c24e2218949): nothing is held. */
export const HOLD_VIEW_EMPTY = 'No held messages.';
/** Rows 335e1 (25, 2c098c744d85944f) and 335e2 (33, d6d581a4b235b997): the per-note times. The sender's is labelled as THEIRS (an unverified clock). */
export const HOLD_VIEW_ARRIVED = 'Arrived here {local_time}';
export const HOLD_VIEW_SENT_BY_THEIR_CLOCK = 'Sent {their_time}, by their clock';
/** Row 335f (38, f3711066f33a610d): the mark on a note the sweep has marked. "Can be removed after", not "will be removed on": the sweep may run later. */
export const HOLD_VIEW_EXPIRING = 'Expiring. Can be removed after {date}.';
/** Rows 335g1 (13, 6e4275ea7b1f7306) and 335g2 (17, dc183884d96864f7): the move buttons. No confirm. */
export const HOLD_VIEW_MOVE_ONE = 'Move to inbox';
export const HOLD_VIEW_MOVE_ALL = 'Move all to inbox';
/** Rows 335g3 (44, de425f254a10f998) and 335g4 (54, 0787b436e8f6a49d): the move results. "Still frozen" is true: moving never unblocks. */
export const HOLD_VIEW_MOVED_ONE = 'Moved to your inbox. {name} is still frozen.';
export const HOLD_VIEW_MOVED_ALL = 'Moved {n} notes to your inbox. {name} is still frozen.';
/** Rows 335h1 (6, e2d0a54968ead24e) and 335h2 (10, 978111835dfadd7a): the delete buttons. */
export const HOLD_VIEW_DELETE_ONE = 'Delete';
export const HOLD_VIEW_DELETE_ALL = 'Delete all';
/** Rows 335h3 (39, ef7e4cbc002e4bca) and 335h4 (60, 79dc9cb06b3402ee): the confirms. Buttons are Cancel (the DEFAULT) and Delete. "Can't be undone" is true only while no copy of held notes exists elsewhere. */
export const HOLD_VIEW_CONFIRM_DELETE_ONE = "Delete this note? This can't be undone.";
export const HOLD_VIEW_CONFIRM_DELETE_ALL = "Delete all {n} held notes from {name}? This can't be undone.";
export const HOLD_VIEW_CONFIRM_CANCEL = 'Cancel';
export const HOLD_VIEW_CONFIRM_DELETE = HOLD_VIEW_DELETE_ONE;
/** Rows 335i1 (40, 00120e5e45f32d86) and 335i2 (38, 5ec60e7754f94249): ONE note failed, and one note's write is all-or-nothing. */
export const HOLD_VIEW_FAILED_DELETE_ONE = "That didn't delete. Nothing was changed.";
export const HOLD_VIEW_FAILED_MOVE_ONE = "That didn't move. Nothing was changed.";
/** Rows 335i3 (47, 4abc03eb8cde6dd3) and 335i4 (45, b0302797d650f352): a loop over ALL can stop part-way, so these say how many are still here ({k}, re-counted after the failure). */
export const HOLD_VIEW_FAILED_DELETE_ALL = "Some notes weren't deleted. {k} are still here.";
export const HOLD_VIEW_FAILED_MOVE_ALL = "Some notes weren't moved. {k} are still here.";

/** What a contact with no name is called in the sentences above (a removed contact has no page and may have no name). */
export const HOLD_VIEW_NO_NAME = 'this person';

/**
 * Fill a template's {placeholders}. One pass over the TEMPLATE only: a value is inserted as it is and never searched again (a name that contains "{n}" or "$&" stays a name). A placeholder with no value
 * THROWS (a sentence with a hole in it must never reach the screen), and so does a value nobody asked for (a typo in a key must fail loudly).
 */
export function fill(template: string, values: Record<string, string | number>): string {
  const wanted = new Set<string>();
  const out = template.replace(/\{([a-z_]+)\}/g, (_m, key: string) => {
    wanted.add(key);
    if (!(key in values)) throw new Error(`hold view copy: no value for {${key}}`);
    return String(values[key]);
  });
  for (const k of Object.keys(values)) if (!wanted.has(k)) throw new Error(`hold view copy: {${k}} is not in this sentence`);
  return out;
}

/** The name to say: the contact's, or "this person". */
export const holdViewName = (name: string | null | undefined): string => (name && name.trim() ? name.trim() : HOLD_VIEW_NO_NAME);

export const holdViewIntro = (name: string | null | undefined): string => fill(HOLD_VIEW_INTRO, { name: holdViewName(name) });
/** The age line, or null when the limit is 0 or not a positive number (the off switch: nothing is removed, so nothing is said). */
export const holdViewAgeLine = (days: number, grace: number): string | null => (Number.isFinite(days) && days > 0 ? fill(HOLD_VIEW_AGE_LINE, { days, grace }) : null);
export const holdViewCapLine = (cap: number): string => fill(HOLD_VIEW_CAP_LINE, { cap });
export const holdViewArrived = (localTime: string): string => fill(HOLD_VIEW_ARRIVED, { local_time: localTime });
export const holdViewSentByTheirClock = (theirTime: string): string => fill(HOLD_VIEW_SENT_BY_THEIR_CLOCK, { their_time: theirTime });
export const holdViewExpiring = (date: string): string => fill(HOLD_VIEW_EXPIRING, { date });
export const holdViewMovedOne = (name: string | null | undefined): string => fill(HOLD_VIEW_MOVED_ONE, { name: holdViewName(name) });
export const holdViewMovedAll = (n: number, name: string | null | undefined): string => fill(HOLD_VIEW_MOVED_ALL, { n, name: holdViewName(name) });
export const holdViewConfirmDeleteAll = (n: number, name: string | null | undefined): string => fill(HOLD_VIEW_CONFIRM_DELETE_ALL, { n, name: holdViewName(name) });
export const holdViewFailedDeleteAll = (stillHere: number): string => fill(HOLD_VIEW_FAILED_DELETE_ALL, { k: stillHere });
export const holdViewFailedMoveAll = (stillHere: number): string => fill(HOLD_VIEW_FAILED_MOVE_ALL, { k: stillHere });
