/**
 * Persist Trust Map node positions so neighborhoods feel like *your* map.
 * Pure UI — no trust semantics. Soft-merge with fresh layout on load.
 *
 * When witnessed mutual topology changes (new person with mutual bonds),
 * blend softens so springs can rearrange the lattice.
 */

const PREFIX = 'svrnty.trust-map.layout.v1:';

export type StoredNodePos = { id: string; x: number; y: number };

export type LayoutMemoryPayload = {
  nodes: Map<string, StoredNodePos>;
  /** Sorted mutual-bond fingerprint; empty if legacy / unknown. */
  topology: string;
};

function key(ownerFingerprint: string): string {
  return `${PREFIX}${ownerFingerprint.toLowerCase()}`;
}

/** Stable fingerprint of witnessed mutual chords (order-independent). */
export function mutualTopologySignature(
  bonds: Array<{ a: string; b: string }>,
): string {
  return bonds
    .map((b) => {
      const x = (b.a || '').toLowerCase();
      const y = (b.b || '').toLowerCase();
      return x < y ? `${x}|${y}` : `${y}|${x}`;
    })
    .filter((k) => k !== '|')
    .sort()
    .join(';');
}

export function loadLayoutMemory(ownerFingerprint: string): LayoutMemoryPayload {
  const nodes = new Map<string, StoredNodePos>();
  if (typeof localStorage === 'undefined' || !ownerFingerprint) {
    return { nodes, topology: '' };
  }
  try {
    const raw = localStorage.getItem(key(ownerFingerprint));
    if (!raw) return { nodes, topology: '' };
    const parsed = JSON.parse(raw) as
      | StoredNodePos[]
      | { nodes?: StoredNodePos[]; topology?: string };
    const list = Array.isArray(parsed) ? parsed : parsed?.nodes;
    const topology =
      !Array.isArray(parsed) && typeof parsed?.topology === 'string'
        ? parsed.topology
        : '';
    if (!Array.isArray(list)) return { nodes, topology: '' };
    for (const p of list) {
      if (p && typeof p.id === 'string' && Number.isFinite(p.x) && Number.isFinite(p.y)) {
        nodes.set(p.id, p);
      }
    }
    return { nodes, topology };
  } catch {
    return { nodes, topology: '' };
  }
}

export function saveLayoutMemory(
  ownerFingerprint: string,
  nodes: StoredNodePos[],
  topology = '',
): void {
  if (typeof localStorage === 'undefined' || !ownerFingerprint) return;
  const slim = nodes
    .filter((n) => n.id && Number.isFinite(n.x) && Number.isFinite(n.y))
    .map((n) => ({ id: n.id, x: n.x, y: n.y }));
  localStorage.setItem(
    key(ownerFingerprint),
    JSON.stringify({ nodes: slim, topology }),
  );
}

/**
 * Blend remembered positions into a fresh layout (0 = fresh, 1 = memory).
 * When `topologyChanged`, use a softer recall so mutual springs can re-settle.
 */
export function applyLayoutMemory<T extends { id: string; x: number; y: number }>(
  nodes: T[],
  memory: Map<string, StoredNodePos>,
  blend = 0.85,
  topologyChanged = false,
): T[] {
  if (memory.size === 0) return nodes;
  const b = topologyChanged ? Math.min(blend, 0.28) : blend;
  return nodes.map((n) => {
    const m = memory.get(n.id);
    if (!m) return n;
    return {
      ...n,
      x: m.x * b + n.x * (1 - b),
      y: m.y * b + n.y * (1 - b),
    };
  });
}
