// src/components/relay/relay-holds-refresh.ts
// The refresh button's own minimum gap. Opening the panel makes no request (it shows the last read the revoke check kept); the button asks that same check to read the relay again, and not more often than this.
// The gap is above the revoke check's own spacing (DRAIN_MIN_GAP_MS), which is what actually protects the relay's rate bucket; a clock that moved back never freezes the button for that reason.
export const REFRESH_MIN_GAP_MS = 10_000;

export function canRefresh(lastPressAt: number | undefined, now: number): { allowed: boolean; waitMs: number } {
  if (lastPressAt === undefined || !Number.isFinite(lastPressAt)) return { allowed: true, waitMs: 0 };
  const elapsed = now - lastPressAt;
  if (elapsed < 0) return { allowed: true, waitMs: 0 };
  if (elapsed >= REFRESH_MIN_GAP_MS) return { allowed: true, waitMs: 0 };
  return { allowed: false, waitMs: REFRESH_MIN_GAP_MS - elapsed };
}
