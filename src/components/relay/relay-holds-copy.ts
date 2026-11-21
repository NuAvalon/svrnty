// src/components/relay/relay-holds-copy.ts
// The words on the "what the relay holds about you" panel (the owner's own screen). Reviewed copy: do not reword it here; a change needs the copy owner's new wording and a new length and hash in relay-holds-copy.test.ts.
// Plain ASCII, straight apostrophes. Each template is pinned by length and sha256 prefix in relay-holds-copy.test.ts. Placeholders are written {like_this} and filled by fill() (the one in the held-messages copy: it throws on a hole or an unused value).
//   - The relay's allowed list gates PRIVATE MATCHING, not note delivery (measured in satellite.py): no line about the list says anything about notes, delivery or reaching the owner.
//   - "at a later check", never "the next check": the revoke drain caps per check and retries failures.
//   - Who-added-me has no string and never will: it would show someone else's one-way consent.
//   - A value the relay lists that is not in the book is labelled, never shown: no fingerprint on screen and no lookup.
// Run: npx tsx --test src/components/relay/relay-holds-copy.test.ts
import { fill } from '../held/hold-view-copy';

/** RELAY_OVER_ONE (110, sha256 prefix ed32c8c265cfcaf2) and RELAY_OVER_MANY (112, 85a8418248e6304e): the relay lists people the book does not allow; the revoke check's drain (allowed-revoke.ts) takes them off. */
export const RELAY_OVER_ONE = "The relay still lists 1 person your contacts don't allow. They'll be taken off automatically at a later check.";
export const RELAY_OVER_MANY = "The relay still lists {n} people your contacts don't allow. They'll be taken off automatically at a later check.";
/** RELAY_UNDER_ONE (100, 1b7c2b612e03712e) and RELAY_UNDER_MANY (103, 2790e43d50ae243e): the book allows people the relay does not list. A private match needs BOTH directions listed. */
export const RELAY_UNDER_ONE = "1 person your contacts allow isn't listed at the relay, so a private match with them can't complete.";
export const RELAY_UNDER_MANY = "{n} people your contacts allow aren't listed at the relay, so private matches with them can't complete.";
/** RELAY_REPAIR_WARNING (109, e9fa5106c2671af8): on EVERY row offering Repair, before the press. A press on one device can still undo a block made on another. */
export const RELAY_REPAIR_WARNING = "If you blocked or removed this person on another device, don't repair: it would list them at the relay again.";
/** RELAY_COULD_NOT_CHECK (92, 547bab26794cd244): the read failed or is unknown. Never an empty list, never "nothing listed". */
export const RELAY_COULD_NOT_CHECK = "We couldn't check what the relay lists right now, so nothing is shown here. Try again later.";
/** RELAY_NO_LIST (89, 2cff53eb21f7f84f): ONLY when the relay says it keeps no list (it answers 410). Until then this line must not render. */
export const RELAY_NO_LIST = "The relay no longer keeps a list of your allowed contacts, so there's nothing to compare.";
/** RELAY_NO_KEY_ONE (109, 510701924dfebdc2) and RELAY_NO_KEY_MANY (112, 87bacd95606ad33a): contacts the book allows who have NO KEY yet. They can never be listed and are missing from the comparison; a plain fact with no Repair ("nothing to fix here"). Shown beside the over/under lines in EVERY ok state, including when those are empty; the nothing-differs line needs this count to be 0. */
export const RELAY_NO_KEY_ONE = "1 person your contacts allow has no key yet, so the relay can't list them. Nothing to fix here until they do.";
export const RELAY_NO_KEY_MANY = "{n} people your contacts allow have no key yet, so the relay can't list them. Nothing to fix here until they do.";
/** RELAY_BOOK_DAMAGED (117, 3ad5425a3d99d0f4; it replaces an earlier wording): the integrity flag is not ok. No rows and no Repair are shown with it. "Can't be FULLY compared": the revoke check still takes off held people the book does not allow; only people ABSENT from a damaged book are skipped. "This page changed nothing" is true of the page, not of the relay. */
export const RELAY_BOOK_DAMAGED = "Your contact list on this device is damaged, so it can't be fully compared with the relay. This page changed nothing.";
/** RELAY_UNKNOWN_SENDER (28, 1723d169cc1ac731): the label for ANY relay-listed value that is not in the book. No fingerprint on screen, no lookup. */
export const RELAY_UNKNOWN_SENDER = 'Someone not in your contacts';
/** RELAY_PANEL_TITLE (20, 2308930139ab8186): the entry label beside the other Lenses & vault entries AND the panel's title. No count and no digit, ever. */
export const RELAY_PANEL_TITLE = 'What the relay lists';
export const RELAY_ENTRY = RELAY_PANEL_TITLE;
/** RELAY_REFRESH_BUTTON (11, fb7099ad8e818d42): asks the revoke check to read the relay again. The same label while the button waits out its gap: no extra line. */
export const RELAY_REFRESH_BUTTON = 'Check again';
/** RELAY_ALL_MATCH (55, 787255c26ff7013d): ONLY after a read that worked, with zero over-listed, zero under-listed and an intact book, and always beside the 'Checked ...' line, so it describes that read and promises nothing about now. */
export const RELAY_ALL_MATCH = 'The relay lists exactly the people your contacts allow.';
/** RELAY_REPAIR_BUTTON (6, 1196b6c538ecc61a): the button. */
export const RELAY_REPAIR_BUTTON = 'Repair';
/** RELAY_REPAIRED (36, 58c18f827cc97a99): only after the relay CONFIRMS the add. {name} starts the sentence. */
export const RELAY_REPAIRED = '{name} is listed at the relay again.';
/** RELAY_REPAIR_FAILED (94, dc5dd76d3e6c930e): anything the relay did not confirm. Says nothing else changed. */
export const RELAY_REPAIR_FAILED = "The relay didn't confirm, so {name} still isn't listed. Nothing else changed. Try again later.";
/** RELAY_REPAIR_GONE (67, 32f9307b0aa83069): the press-time re-check found the contact no longer allowed; nothing is sent. */
export const RELAY_REPAIR_GONE = "Your contacts no longer allow {name}, so there's nothing to repair.";
/** RELAY_CHECKED_NOW (17, 8291e345581b88d9), RELAY_CHECKED_MINUTES (20, 5a6f32a7a65bf53d), RELAY_CHECKED_HOUR (25, 9948a8eb28db0b5d): when the list was last read. Shown ONLY after a drain that actually read it. */
export const RELAY_CHECKED_NOW = 'Checked just now.';
export const RELAY_CHECKED_MINUTES = 'Checked {n} min ago.';
export const RELAY_CHECKED_HOUR = 'Checked over an hour ago.';
/** RELAY_BY_DESIGN (101, 02a58139d08b6b74; it replaces an earlier wording): once, in the panel's own copy, not per row. "Can't read who a note is from", not "can't see who sent it": the relay does see each deposit's network address and time, but verifies no sender identity and cannot read the sealed content. */
export const RELAY_BY_DESIGN = "The relay can't read who a note is from, so notes can't be counted per person here. That's by design.";

const MINUTE_MS = 60_000;

function whole(n: number, what: string): number {
  if (!Number.isInteger(n) || n < 0) throw new Error(`relay-holds copy: ${what} must be a whole number >= 0`);
  return n;
}

/** A contact's name for a sentence, or "this person"; capitalised when it starts the sentence. */
function nameFor(name: string | null | undefined, startOfSentence: boolean): string {
  const t = typeof name === 'string' ? name.trim() : '';
  if (t) return t;
  return startOfSentence ? 'This person' : 'this person';
}

/** RELAY_OVER_ONE / RELAY_OVER_MANY: null for 0 (an empty diff shows no line). */
export function overListedLine(count: number): string | null {
  const n = whole(count, 'count');
  if (n === 0) return null;
  return n === 1 ? RELAY_OVER_ONE : fill(RELAY_OVER_MANY, { n });
}

/** RELAY_UNDER_ONE / RELAY_UNDER_MANY: null for 0. */
export function underListedLine(count: number): string | null {
  const n = whole(count, 'count');
  if (n === 0) return null;
  return n === 1 ? RELAY_UNDER_ONE : fill(RELAY_UNDER_MANY, { n });
}

/** RELAY_NO_KEY_ONE / RELAY_NO_KEY_MANY: null for 0. */
export function noKeyLine(count: number): string | null {
  const n = whole(count, 'count');
  if (n === 0) return null;
  return n === 1 ? RELAY_NO_KEY_ONE : fill(RELAY_NO_KEY_MANY, { n });
}

/** RELAY_CHECKED_NOW, RELAY_CHECKED_MINUTES or RELAY_CHECKED_HOUR from the age of the last read in ms: under a minute "just now" (a clock that moved back too), 1..59 whole minutes, an hour or more says so. A non-number THROWS: a hole must not reach the screen. */
export function checkedLine(ageMs: number): string {
  if (typeof ageMs !== 'number' || !Number.isFinite(ageMs)) throw new Error('relay-holds copy: age must be a finite number of ms');
  const minutes = Math.floor(ageMs / MINUTE_MS);
  if (minutes < 1) return RELAY_CHECKED_NOW;
  if (minutes < 60) return fill(RELAY_CHECKED_MINUTES, { n: minutes });
  return RELAY_CHECKED_HOUR;
}

/** The label of one row in a list: the contact's name, or "This person" (the row starts its own line). */
export const rowLabel = (name: string | null | undefined): string => nameFor(name, true);

export const repairedLine = (name: string | null | undefined): string => fill(RELAY_REPAIRED, { name: nameFor(name, true) });
export const repairFailedLine = (name: string | null | undefined): string => fill(RELAY_REPAIR_FAILED, { name: nameFor(name, false) });
export const repairGoneLine = (name: string | null | undefined): string => fill(RELAY_REPAIR_GONE, { name: nameFor(name, false) });
