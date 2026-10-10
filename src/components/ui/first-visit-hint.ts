/** Device-local first-visit hint memory. Not identity material. Never published. */

export const HINT_SEEN_KEY = 'svrnty.hint.seen.v1';

type SeenMap = Record<string, true>;

function readMap(): SeenMap {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(HINT_SEEN_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out: SeenMap = {};
    for (const [id, val] of Object.entries(parsed as Record<string, unknown>)) {
      if (val === true && id.trim()) out[id] = true;
    }
    return out;
  } catch {
    return {};
  }
}

export function hintHasBeenSeen(id: string): boolean {
  const key = id.trim();
  if (!key) return false;
  return readMap()[key] === true;
}

export function markHintSeen(id: string): void {
  const key = id.trim();
  if (!key || typeof window === 'undefined') return;
  try {
    const next = { ...readMap(), [key]: true as const };
    window.localStorage.setItem(HINT_SEEN_KEY, JSON.stringify(next));
  } catch {
    /* private mode / quota — hint still toggles this session */
  }
}
