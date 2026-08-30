/**
 * Persist Trust Map node positions so neighborhoods feel like *your* map.
 * Pure UI — no trust semantics. Soft-merge with fresh layout on load.
 */

const PREFIX = 'svrnty.trust-map.layout.v1:';

export type StoredNodePos = { id: string; x: number; y: number };

function key(ownerFingerprint: string): string {
  return `${PREFIX}${ownerFingerprint.toLowerCase()}`;
}

export function loadLayoutMemory(ownerFingerprint: string): Map<string, StoredNodePos> {
  const out = new Map<string, StoredNodePos>();
  if (typeof localStorage === 'undefined' || !ownerFingerprint) return out;
  try {
    const raw = localStorage.getItem(key(ownerFingerprint));
    if (!raw) return out;
    const parsed = JSON.parse(raw) as StoredNodePos[];
    if (!Array.isArray(parsed)) return out;
    for (const p of parsed) {
      if (p && typeof p.id === 'string' && Number.isFinite(p.x) && Number.isFinite(p.y)) {
        out.set(p.id, p);
      }
    }
  } catch {
    /* ignore */
  }
  return out;
}

export function saveLayoutMemory(ownerFingerprint: string, nodes: StoredNodePos[]): void {
  if (typeof localStorage === 'undefined' || !ownerFingerprint) return;
  const slim = nodes
    .filter((n) => n.id && Number.isFinite(n.x) && Number.isFinite(n.y))
    .map((n) => ({ id: n.id, x: n.x, y: n.y }));
  localStorage.setItem(key(ownerFingerprint), JSON.stringify(slim));
}

/** Blend remembered positions into a fresh layout (0 = fresh, 1 = memory). */
export function applyLayoutMemory<T extends { id: string; x: number; y: number }>(
  nodes: T[],
  memory: Map<string, StoredNodePos>,
  blend = 0.85,
): T[] {
  if (memory.size === 0) return nodes;
  return nodes.map((n) => {
    const m = memory.get(n.id);
    if (!m) return n;
    return {
      ...n,
      x: m.x * blend + n.x * (1 - blend),
      y: m.y * blend + n.y * (1 - blend),
    };
  });
}
