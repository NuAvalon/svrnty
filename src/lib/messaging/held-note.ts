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
