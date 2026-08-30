/**
 * Deterministic spacing + gravity for the Social Graph.
 *
 * Pure layout post-process — no crypto, no visibility inference.
 * Owner-authored group tags may softly attract; peer↔peer trust is NEVER invented.
 *
 * Forces (each iteration):
 *   1. Ring gravity — keep Orbit nodes near their intended radius from self
 *   2. Cluster gravity — soft pull toward shared owner-local tags
 *   3. Collision / spacing — push overlapping seals apart
 *   4. Self clearance — keep out of the center seal
 *   5. Bounds clamp — stay inside the viewBox
 */

export type ForceNode = {
  id: string;
  x: number;
  y: number;
  radius: number;
};

export type ForceOptions = {
  width: number;
  height: number;
  /** Center of gravity for Orbit (self). */
  cx: number;
  cy: number;
  /** Preferred distance from center keyed by node id (Orbit rings). */
  preferredRadius?: Map<string, number>;
  /** Owner-authored tag → member ids (cluster gravity only). */
  tagMembers?: Map<string, string[]>;
  /** Min clear gap between seal edges. */
  padding?: number;
  /** Keep nodes outside this radius from center (self seal). */
  selfClearance?: number;
  iterations?: number;
  /** Strength of pull back onto preferred ring [0..1]. */
  ringGravity?: number;
  /** Strength of same-tag centroid pull [0..1]. */
  clusterGravity?: number;
  /** Collision strength multiplier. */
  repulsion?: number;
  margin?: number;
};

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, v));
}

/**
 * Adaptive ring radius so arc spacing stays readable as the roster grows.
 * If count exceeds what maxR can hold, callers should split across rings.
 */
export function radiusForCount(
  count: number,
  minR: number,
  maxR: number,
  minArc = 30,
): number {
  if (count <= 0) return minR;
  const needed = (count * minArc) / (2 * Math.PI);
  return clamp(needed, minR, maxR);
}

/**
 * Split a long roster across concentric rings so seals don't stack on one circle.
 * Returns per-item { ringIndex, indexOnRing, ringCount }.
 */
export function assignConcentricSlots(
  count: number,
  maxPerRing: number,
): Array<{ ring: number; index: number; onRing: number }> {
  if (count <= 0) return [];
  const rings = Math.max(1, Math.ceil(count / Math.max(1, maxPerRing)));
  const base = Math.floor(count / rings);
  const rem = count % rings;
  const out: Array<{ ring: number; index: number; onRing: number }> = [];
  let cursor = 0;
  for (let r = 0; r < rings; r++) {
    const onRing = base + (r < rem ? 1 : 0);
    for (let i = 0; i < onRing; i++) {
      out[cursor++] = { ring: r, index: i, onRing };
    }
  }
  return out;
}

/**
 * Relax node positions with spacing + gravity. Deterministic; no Math.random.
 */
export function relaxGraphNodes<T extends ForceNode>(
  input: T[],
  opts: ForceOptions,
): T[] {
  const {
    width,
    height,
    cx,
    cy,
    preferredRadius,
    tagMembers,
    padding = 14,
    selfClearance = 42,
    iterations = 48,
    ringGravity = 0.18,
    clusterGravity = 0.12,
    repulsion = 0.55,
    margin = 22,
  } = opts;

  const nodes = input.map((n) => ({ ...n }));
  const byId = new Map(nodes.map((n) => [n.id, n]));

  for (let iter = 0; iter < iterations; iter++) {
    const cool = 1 - iter / iterations; // ease out

    // 1) Ring gravity — restore Orbit structure after collisions shove nodes
    if (preferredRadius && preferredRadius.size > 0) {
      for (const n of nodes) {
        const pref = preferredRadius.get(n.id);
        if (pref == null) continue;
        const dx = n.x - cx;
        const dy = n.y - cy;
        const dist = Math.hypot(dx, dy) || 1e-6;
        const targetX = cx + (dx / dist) * pref;
        const targetY = cy + (dy / dist) * pref;
        n.x += (targetX - n.x) * ringGravity * cool;
        n.y += (targetY - n.y) * ringGravity * cool;
      }
    }

    // 2) Cluster gravity — owner tags only (not inferred bonds)
    if (tagMembers) {
      for (const [, ids] of tagMembers) {
        if (ids.length < 2) continue;
        const members = ids.map((id) => byId.get(id)).filter(Boolean) as T[];
        if (members.length < 2) continue;
        const gx = members.reduce((s, m) => s + m.x, 0) / members.length;
        const gy = members.reduce((s, m) => s + m.y, 0) / members.length;
        for (const m of members) {
          m.x += (gx - m.x) * clusterGravity * cool;
          m.y += (gy - m.y) * clusterGravity * cool;
        }
      }
    }

    // 3) Pairwise spacing / collision
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist = Math.hypot(dx, dy);
        const minDist = a.radius + b.radius + padding;
        if (dist < 1e-6) {
          // Deterministic nudge from id hash so stacked nodes separate
          let h = 0;
          for (let k = 0; k < a.id.length; k++) h = (h * 31 + a.id.charCodeAt(k)) | 0;
          const ang = ((h >>> 0) % 360) * (Math.PI / 180);
          dx = Math.cos(ang);
          dy = Math.sin(ang);
          dist = 1e-6;
        }
        if (dist >= minDist) continue;
        const push = ((minDist - dist) / dist) * 0.5 * repulsion * (0.35 + 0.65 * cool);
        const ox = dx * push;
        const oy = dy * push;
        a.x -= ox;
        a.y -= oy;
        b.x += ox;
        b.y += oy;
      }
    }

    // 4) Self clearance + bounds
    for (const n of nodes) {
      const dx = n.x - cx;
      const dy = n.y - cy;
      const dist = Math.hypot(dx, dy) || 1e-6;
      const minR = selfClearance + n.radius;
      if (dist < minR) {
        n.x = cx + (dx / dist) * minR;
        n.y = cy + (dy / dist) * minR;
      }
      n.x = clamp(n.x, margin + n.radius, width - margin - n.radius);
      n.y = clamp(n.y, margin + n.radius, height - margin - n.radius - 8);
    }
  }

  return nodes;
}

/** Build tag → member ids from contacts (owner-local tags only). */
export function tagMembership(
  contacts: Array<{ peer_fingerprint: string; tags?: string[] }>,
): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const c of contacts) {
    for (const t of c.tags || []) {
      if (!t) continue;
      const list = map.get(t) || [];
      list.push(c.peer_fingerprint);
      map.set(t, list);
    }
  }
  return map;
}
