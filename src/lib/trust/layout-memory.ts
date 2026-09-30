/**
 * Persist Trust Map node positions so neighborhoods feel like *your* map.
 * Pure UI — no trust semantics. Soft-merge with fresh layout on load.
 *
 * When witnessed mutual topology OR glass state (known → verified → trusted)
 * changes, blend softens so density / gravity can rearrange the lattice.
 */

const PREFIX = 'svrnty.trust-map.layout.v1:';

export type StoredNodePos = { id: string; x: number; y: number };

export type LayoutMemoryPayload = {
  nodes: Map<string, StoredNodePos>;
  /** Sorted mutual-bond fingerprint; empty if legacy / unknown. */
  topology: string;
  /** Known / verified / trusted per peer — owner-local glass, not a public badge. */
  glass: string;
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

/**
 * Owner-local glass fingerprint (known / verified / trusted).
 * Order-independent. Verify is private — this signature never leaves the device.
 */
export function glassStateSignature(
  nodes: Array<{ id: string; state: string; verified?: boolean }>,
): string {
  return nodes
    .map((n) => {
      const id = (n.id || '').toLowerCase();
      const v = n.verified ? 'v' : '';
      return `${id}:${n.state}${v}`;
    })
    .filter((k) => !k.startsWith(':'))
    .sort()
    .join(';');
}

export function loadLayoutMemory(ownerFingerprint: string): LayoutMemoryPayload {
  const empty = { nodes: new Map<string, StoredNodePos>(), topology: '', glass: '' };
  if (typeof localStorage === 'undefined' || !ownerFingerprint) {
    return empty;
  }
  try {
    const raw = localStorage.getItem(key(ownerFingerprint));
    if (!raw) return empty;
    const parsed = JSON.parse(raw) as
      | StoredNodePos[]
      | { nodes?: StoredNodePos[]; topology?: string; glass?: string };
    const list = Array.isArray(parsed) ? parsed : parsed?.nodes;
    const topology =
      !Array.isArray(parsed) && typeof parsed?.topology === 'string'
        ? parsed.topology
        : '';
    const glass =
      !Array.isArray(parsed) && typeof parsed?.glass === 'string' ? parsed.glass : '';
    if (!Array.isArray(list)) return { nodes: empty.nodes, topology, glass };
    const nodes = new Map<string, StoredNodePos>();
    for (const p of list) {
      if (p && typeof p.id === 'string' && Number.isFinite(p.x) && Number.isFinite(p.y)) {
        nodes.set(p.id, p);
      }
    }
    return { nodes, topology, glass };
  } catch {
    return empty;
  }
}

export function saveLayoutMemory(
  ownerFingerprint: string,
  nodes: StoredNodePos[],
  topology = '',
  glass = '',
): void {
  if (typeof localStorage === 'undefined' || !ownerFingerprint) return;
  const slim = nodes
    .filter((n) => n.id && Number.isFinite(n.x) && Number.isFinite(n.y))
    .map((n) => ({ id: n.id, x: n.x, y: n.y }));
  localStorage.setItem(
    key(ownerFingerprint),
    JSON.stringify({ nodes: slim, topology, glass }),
  );
}

/**
 * Blend remembered positions into a fresh layout (0 = fresh, 1 = memory).
 * Topology change (mutual bonds) and glass upgrades (known→trusted) both
 * soften recall so density / gravity can re-pack the hive.
 */
export function applyLayoutMemory<T extends { id: string; x: number; y: number }>(
  nodes: T[],
  memory: Map<string, StoredNodePos>,
  blend = 0.85,
  topologyChanged = false,
  stateChanged = false,
): T[] {
  if (memory.size === 0) return nodes;
  const b = stateChanged
    ? Math.min(blend, 0.14)
    : topologyChanged
      ? Math.min(blend, 0.28)
      : blend;
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
