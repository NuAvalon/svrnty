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
  // A previously stored value is clamped too, so a thread already pinned by the old overwrite rule heals instead of sticking.
  const before = prev === undefined ? NaN : Date.parse(prev);
  const kept = Number.isFinite(before) ? Math.min(before, ceiling) : -Infinity;
  return new Date(Math.max(kept, candidate)).toISOString();
}
