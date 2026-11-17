// src/lib/db-upgrade-blocked.ts
// The one sentence for "another svrnty tab is holding the database open, so an upgrade cannot run" (copy ledger row 245b), and the coded error that carries it.
// The browser fires `onblocked` when a database upgrade is held up by another open connection. That used to reject with a plain Error whose text said
// "close other svrnty tabs and reload": a screen that now shows a fixed sentence for its place would drop that hint, and a reload alone loops while the other tab
// still holds the old database. So the rejection is CODED, and every helper that turns a failure into a sentence asks this module FIRST (by code, never by text).
//   - A leaf on purpose (no imports): a public page can use it without loading any store code.
//   - It is a failure, not a refusal: it is an expected stop, so a helper does not log it as an unknown failure.
//   - The error's own message IS the sentence, so a catch that has not been converted yet and still reads err.message shows the same words as before, not a generic line.
// Run: npx tsx --test src/lib/db-upgrade-blocked.test.ts
export const DB_UPGRADE_BLOCKED_MESSAGE = "Another svrnty tab is holding up an update. Close your other svrnty tabs, then reload this page.";

export class DbUpgradeBlocked extends Error {
  readonly code = 'db-upgrade-blocked' as const;
  constructor() { super(DB_UPGRADE_BLOCKED_MESSAGE); this.name = 'DbUpgradeBlocked'; }
}

/** By code, not instanceof: the store and the screens load through dynamic imports, so the class can be a different copy. */
export function isDbUpgradeBlocked(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === 'db-upgrade-blocked';
}

/** The sentence when the error is the blocked-upgrade failure, else null (the caller then uses its own sentence). */
export function dbUpgradeBlockedMessage(err: unknown): string | null {
  return isDbUpgradeBlocked(err) ? DB_UPGRADE_BLOCKED_MESSAGE : null;
}
