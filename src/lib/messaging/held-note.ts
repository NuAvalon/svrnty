// src/lib/messaging/held-note.ts: the pure rules for a note KEPT from a frozen sender ("held").
// A held note is an ordinary sealed note row whose payload carries `held: true`. The flag lives ONLY inside the encrypted payload: the plaintext
// columns (note_id, thread_id) and the indexes are exactly a normal row's, so the store shows no second kind of row at rest.
// The readers every screen uses drop held rows (fail closed: a screen that is never edited cannot show one); the few that must see them
// (replay guard, cap count, the hold view) ask for them by name. A sender chooses a note's own expiry, so a held note ignores it.

type Flagged = object;   // any row: the flag is read through heldOf, so a real note or thread type-checks (a weak all-optional type would refuse them)
const heldOf = (x: Flagged): unknown => (x as { held?: unknown }).held;

/** Held means exactly `true`: a look-alike value (a string, 1) is an ordinary row, never a hidden one. */
export const isHeldNote = (n: Flagged): boolean => heldOf(n) === true;
export const isHeldThread = (t: Flagged): boolean => heldOf(t) === true;

/**
 * The thread row with its held key removed (a copy; the input is untouched). The ONE place a held flag is ever dropped, and only on a THREAD: an
 * admitted arrival on a thread that exists only because of held notes makes the row an ordinary thread again. The notes in it keep their own
 * flag and stay hidden, so nothing held is shown by this. Pinned to a single caller (held-readers.test.ts S9).
 */
export function clearedHeld<T extends Flagged>(t: T): T {
  return Object.fromEntries(Object.entries(t).filter(([k]) => k !== 'held')) as T;
}

/** What every ordinary reader returns: the rows a person is meant to see. */
export function visibleNotes<T extends Flagged>(notes: readonly T[]): T[] {
  return notes.filter((n) => !isHeldNote(n));
}
export function visibleThreads<T extends Flagged>(threads: readonly T[]): T[] {
  return threads.filter((t) => !isHeldThread(t));
}

/**
 * Whether the sender-set expiry has passed. The rule an ordinary note always had: a real time strictly in the past (an unparseable date compares
 * false, so it never expires a note). A held note never expires on the sender's say-so: only the hold's own age limit may remove it.
 */
export function noteExpired(note: Flagged & { retention: { expires_at: string | null } }, nowMs: number): boolean {
  if (isHeldNote(note)) return false;
  const at = note.retention.expires_at;
  return !!at && new Date(at).getTime() < nowMs;
}

/** The most notes ONE frozen sender can have held at once. PETER'S NUMBER, provisional (ruled: past it the note is NOT stored and gets NO receipt: the same drop a stranger gets). */
export const HOLD_CAP_PER_SENDER = 500;

/**
 * The hold's AGE LIMIT, in days: PETER'S NUMBER (30). 0 = the off switch: nothing is ever deleted (and nothing is stamped as expiring). One named number, read in ONE place (heldSweepAction's default),
 * never scattered at call sites: a later owner-facing setting changes this one line's source, not the rule.
 */
export const HOLD_AGE_LIMIT_DAYS = 30;
/** After the sweep FIRST sees a held note past the limit it only stamps it; the note is deleted no sooner than this many days after that stamp (a wrong device date that persists gets this long to be noticed). */
export const HOLD_EXPIRY_GRACE_DAYS = 7;
const DAY_MS = 86_400_000;

/** What the age sweep does to ONE held note. Only 'delete' removes anything; the others rewrite the sealed row's own two stamps. */
export type HeldSweepAction = 'keep' | 'stamp-held-at' | 'stamp-expiry' | 'clear-expiry' | 'delete';

const timeMs = (v: unknown): number | null => {
  if (typeof v !== 'string') return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
};

/**
 * The ONE rule for the age limit, on the OWNER'S clock (`nowMs`). A note's age runs from `held_at`, which the owner's device wrote when it first held the note: never from sent_at (the sender signs
 * that, so a frozen sender could backdate a note and have the owner's evidence deleted) and never from the sender's retention. Unknown age means KEEP: a held note with no held_at (held before the
 * field existed) or one that does not parse is STAMPED, never deleted on sight. Past the limit the first sweep only stamps `expiry_seen_at`; deletion needs the limit AND a grace after that stamp. If the
 * clock is put back so the note is no longer past the limit, the stamp is cleared. A stamp in the future (a clock that went back) never deletes. A limit that is 0, negative or not a number deletes nothing.
 */
export function heldSweepAction(note: Flagged & { held_at?: unknown; expiry_seen_at?: unknown }, nowMs: number, limitDays: number = HOLD_AGE_LIMIT_DAYS, graceDays: number = HOLD_EXPIRY_GRACE_DAYS): HeldSweepAction {
  if (!isHeldNote(note)) return 'keep';
  if (!(limitDays > 0) || !Number.isFinite(nowMs)) return 'keep';
  const heldAt = timeMs(note.held_at);
  if (heldAt === null) return 'stamp-held-at';
  const pastLimit = nowMs - heldAt >= limitDays * DAY_MS;
  if (!pastLimit) return note.expiry_seen_at === undefined ? 'keep' : 'clear-expiry';
  const seen = timeMs(note.expiry_seen_at);
  if (seen === null) return 'stamp-expiry';
  if (seen > nowMs) return 'keep';
  return nowMs - seen >= graceDays * DAY_MS ? 'delete' : 'keep';
}

/** The row a stamping action leaves behind (a copy; the input is untouched). 'keep' and 'delete' return the note as it is: a delete is done by the counted delete, never by this. */
export function stampedHeldNote<T extends Flagged & { held_at?: string; expiry_seen_at?: string }>(note: T, action: HeldSweepAction, nowMs: number): T {
  const iso = new Date(nowMs).toISOString();
  const rest = Object.fromEntries(Object.entries(note).filter(([k]) => k !== 'expiry_seen_at')) as T;   // a copy without the expiry stamp (the same way clearedHeld drops a key)
  if (action === 'stamp-held-at') return { ...rest, held_at: iso };   // unknown age: start the clock now, and forget any stamp that was made against an age we do not know
  if (action === 'stamp-expiry') return { ...note, expiry_seen_at: iso };
  if (action === 'clear-expiry') return rest;
  return note;
}

/**
 * The two stamps a note gets as it is HELD, on the OWNER'S clock. The ONE place `held_at` is first written (acceptInboundNote's held branch calls this and nothing else does). A redelivery of a note this
 * device already holds KEEPS the stamps it has (the age is when it was first held, so a sender cannot restart or stall it by sending the note again); anything else, including a held note from before
 * the field existed, starts the clock now. The wire never reaches this: only the stored prior row and the owner's own clock do.
 */
export function heldStampsFor(prior: (Flagged & { held_at?: unknown; expiry_seen_at?: unknown }) | null | undefined, nowMs: number): { held_at: string; expiry_seen_at?: string } {
  if (prior && isHeldNote(prior) && timeMs(prior.held_at) !== null) {
    const stamps: { held_at: string; expiry_seen_at?: string } = { held_at: prior.held_at as string };
    if (typeof prior.expiry_seen_at === 'string') stamps.expiry_seen_at = prior.expiry_seen_at;
    return stamps;
  }
  return { held_at: new Date(nowMs).toISOString() };
}
