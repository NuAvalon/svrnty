// Chat-list order: a thread's last_activity_at is the newest PLAUSIBLE message time we hold, never "the last note we happened to process".
// sent_at is chosen by the sender, so it is clamped at RECEIPT (the stored value is the clamped one, never the raw one): one note dated
// 2099 cannot hold a contact at the top of the list, and a backlog note older than the thread's activity cannot move the contact down.

/** Same 5-minute slack the ratchet adopt policy (R5) allows for sender clock skew. */
export const ACTIVITY_FUTURE_SLACK_MS = 5 * 60_000;

/** Returns the ISO time to store as `last_activity_at` after a note stamped `sentAt` was processed at `nowMs`. */
export function nextLastActivity(prev: string | undefined, sentAt: string, nowMs: number): string {
  const ceiling = nowMs + ACTIVITY_FUTURE_SLACK_MS;
  const sent = Date.parse(sentAt);
  // An unparsable sender time carries no ordering information: count it as "now".
  const candidate = Math.min(Number.isFinite(sent) ? sent : nowMs, ceiling);
  // A previously stored value is clamped too, so a thread already pinned by the old overwrite rule heals on its NEXT note instead of sticking.
  // Until a note arrives nothing rewrites it: the stored value is unchanged and a list that sorts on it still shows the pin.
  const before = prev === undefined ? NaN : Date.parse(prev);
  const kept = Number.isFinite(before) ? Math.min(before, ceiling) : -Infinity;
  return new Date(Math.max(kept, candidate)).toISOString();
}

// ── Healing a thread that is already pinned in the future ────────────────────────────────────────────────────────────────────────────────
// nextLastActivity clamps at RECEIPT, so a thread pinned by the older overwrite rule (or by a note dated far ahead before the clamp existed) keeps its
// stored future value until a note arrives IN that thread. A value that is only clamped when READ moves with the clock, so the thread would stay above
// every thread with real activity forever. Healing writes a fixed, lower value ONCE, after which ordinary activity overtakes it.

/** True when the stored value is parseable and later than now + the allowed slack. An unparseable value is not healed (it sorts last, see readLastActivity). */
export function needsLastActivityHeal(stored: string, nowMs: number): boolean {
  const t = Date.parse(stored);
  return Number.isFinite(t) && t > nowMs + ACTIVITY_FUTURE_SLACK_MS;
}

/**
 * The value to store for a pinned thread, or null when it needs no heal. It only ever LOWERS a value.
 *  - notes at hand with at least one plausible sent_at (not later than now + slack): the newest of those, so the thread lands where its real
 *    messages put it;
 *  - notes at hand but none plausible (the pinning note is the only one): no honest anchor exists, so "now", the moment this was noticed;
 *    a thread's own created_at is NOT used, because it is copied from the first note's sender-chosen sent_at;
 *  - notes not available: now + slack, the ceiling that every other path already clamps to.
 */
export function healedLastActivity(stored: string, noteSentAts: readonly string[] | null, nowMs: number): string | null {
  if (!needsLastActivityHeal(stored, nowMs)) return null;
  const ceiling = nowMs + ACTIVITY_FUTURE_SLACK_MS;
  let value: number;
  if (noteSentAts === null) {
    value = ceiling;
  } else {
    const plausible = noteSentAts.map((s) => Date.parse(s)).filter((t) => Number.isFinite(t) && t <= ceiling);
    value = plausible.length > 0 ? Math.max(...plausible) : nowMs;
  }
  return new Date(Math.min(value, Date.parse(stored))).toISOString();
}

/**
 * The time to SORT and SHOW a thread by: the stored value, held to now + slack, and an unreadable value sorts last. This is the backstop for a heal
 * that could not be written; it never changes what is stored.
 */
export function readLastActivity(stored: string, nowMs: number): string {
  const t = Date.parse(stored);
  if (!Number.isFinite(t)) return new Date(0).toISOString();
  const ceiling = nowMs + ACTIVITY_FUTURE_SLACK_MS;
  return t <= ceiling ? stored : new Date(ceiling).toISOString();
}
