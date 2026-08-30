/**
 * Deterministic spacing + gravity for the Social Graph.
 *
 * Organic lattice — NOT concentric trust rings. Trust is an overlay (glow),
 * never a radius from self. Owner-authored group tags may softly attract;
 * peer↔peer trust is NEVER invented.
 *
 * Forces (each iteration):
 *   1. Soft cloud keep — stay in a wide disk around self (not a ring)
 *   2. Cluster gravity — pull toward shared owner-local tags
 *   3. Collision / spacing — push overlapping seals apart
 *   4. Self clearance — keep out of the center seal
 *   5. Bounds clamp — stay inside the world
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
  /** Center of gravity (self). */
  cx: number;
  cy: number;
  /** Owner-authored tag → member ids (cluster gravity only). */
  tagMembers?: Map<string, string[]>;
  /** Min clear gap between seal edges. */
  padding?: number;
  /** Keep nodes outside this radius from center (self seal). */
  selfClearance?: number;
  iterations?: number;
  /** Strength of same-tag centroid pull [0..1]. */
  clusterGravity?: number;
  /** Weak pull toward self so the cloud stays egocentric [0..1]. */
  centerGravity?: number;
  /** Wide disk — radial force ONLY outside this band (not a ring). */
  cloudMin?: number;
  cloudMax?: number;
  /** Collision strength multiplier. */
  repulsion?: number;
  margin?: number;
};

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, v));
}

export function hash32(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const GOLDEN = Math.PI * (3 - Math.sqrt(5));

/**
 * Vogel sunflower seed — even packing without discrete rings.
 * Deterministic; optional angular offset from a hash.
 */
export function seedPhyllotaxis(
  count: number,
  cx: number,
  cy: number,
  minR: number,
  spread: number,
  angle0 = 0,
): Array<{ x: number; y: number }> {
  if (count <= 0) return [];
  const out: Array<{ x: number; y: number }> = [];
  for (let i = 0; i < count; i++) {
    const r = minR + spread * Math.sqrt((i + 0.5) / count);
    const theta = angle0 + i * GOLDEN;
    out.push({ x: cx + Math.cos(theta) * r, y: cy + Math.sin(theta) * r });
  }
  return out;
}

/**
 * Seed around self: same-tag contacts share a sector (neighborhood),
 * radii grow with index (not with trust). Untagged scatter by phyllotaxis.
 */
export function seedEgocentric(
  ids: Array<{ id: string; tags?: string[] }>,
  cx: number,
  cy: number,
  minR: number,
  spread: number,
): Array<{ id: string; x: number; y: number }> {
  const tagAngle = new Map<string, number>();
  const seenTags: string[] = [];
  for (const item of ids) {
    const primary = (item.tags || []).find((t) => !!t);
    if (primary && !tagAngle.has(primary)) {
      seenTags.push(primary);
      tagAngle.set(primary, 0);
    }
  }
  const nTags = Math.max(seenTags.length, 1);
  seenTags.forEach((t, i) => {
    const jitter = ((hash32(t) % 100) / 100 - 0.5) * 0.22;
    tagAngle.set(t, (i / nTags) * Math.PI * 2 - Math.PI / 2 + jitter);
  });
  const out: Array<{ id: string; x: number; y: number }> = [];
  for (let i = 0; i < ids.length; i++) {
    const item = ids[i];
    const primary = (item.tags || []).find((t) => !!t);
    const jitter = (hash32(item.id) % 1000) / 1000;
    let theta: number;
    let r: number;
    if (primary) {
      if (!tagAngle.has(primary)) {
        tagAngle.set(primary, ((hash32(primary) % 360) * Math.PI) / 180);
      }
      const base = tagAngle.get(primary)!;
      const slot = (hash32(item.id + primary) % 1000) / 1000;
      theta = base + (slot - 0.5) * 0.95;
      r = minR + spread * (0.22 + jitter * 0.78) + Math.sqrt(i + 1) * 9;
    } else {
      theta = i * GOLDEN + jitter * 0.55;
      r = minR + spread * Math.sqrt((i + 0.35) / Math.max(ids.length, 1));
    }
    out.push({
      id: item.id,
      x: cx + Math.cos(theta) * r,
      y: cy + Math.sin(theta) * r,
    });
  }
  return out;
}

/**
 * Relax node positions. Deterministic; no Math.random.
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
    tagMembers,
    padding = 14,
    selfClearance = 42,
    iterations = 48,
    clusterGravity = 0.14,
    centerGravity = 0.035,
    cloudMin = 0,
    cloudMax = 0,
    repulsion = 0.55,
    margin = 22,
  } = opts;

  const nodes = input.map((n) => ({ ...n }));
  const byId = new Map(nodes.map((n) => [n.id, n]));

  for (let iter = 0; iter < iterations; iter++) {
    const cool = 1 - iter / iterations;

    // 1) Wide cloud keep — radial force only if outside the band
    if (cloudMax > cloudMin && cloudMax > 0) {
      for (const n of nodes) {
        const dx = n.x - cx;
        const dy = n.y - cy;
        const dist = Math.hypot(dx, dy) || 1e-6;
        if (dist > cloudMax) {
          const t = ((dist - cloudMax) / dist) * 0.22 * cool;
          n.x -= dx * t;
          n.y -= dy * t;
        } else if (dist < cloudMin && dist > 0) {
          const t = ((cloudMin - dist) / dist) * 0.18 * cool;
          n.x += dx * t;
          n.y += dy * t;
        }
      }
    }

    // Weak egocentric pull so the lattice doesn't drift into a corner
    if (centerGravity > 0) {
      for (const n of nodes) {
        n.x += (cx - n.x) * centerGravity * cool;
        n.y += (cy - n.y) * centerGravity * cool;
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

    // 3) Spatial-hash collision — O(n) neighborhood, so 2000-book density stays interactive
    const maxR = nodes.reduce((m, n) => Math.max(m, n.radius), 8);
    const cell = Math.max(maxR * 2 + padding, 24);
    const buckets = new Map<string, number[]>();
    const cellKey = (x: number, y: number) =>
      `${Math.floor(x / cell)}:${Math.floor(y / cell)}`;
    for (let i = 0; i < nodes.length; i++) {
      const k = cellKey(nodes[i].x, nodes[i].y);
      const list = buckets.get(k);
      if (list) list.push(i);
      else buckets.set(k, [i]);
    }
    const collide = (i: number, j: number) => {
      const a = nodes[i];
      const b = nodes[j];
      let dx = b.x - a.x;
      let dy = b.y - a.y;
      let dist = Math.hypot(dx, dy);
      const minDist = a.radius + b.radius + padding;
      if (dist < 1e-6) {
        const ang = ((hash32(a.id) % 360) * Math.PI) / 180;
        dx = Math.cos(ang);
        dy = Math.sin(ang);
        dist = 1e-6;
      }
      if (dist >= minDist) return;
      const push = ((minDist - dist) / dist) * 0.5 * repulsion * (0.35 + 0.65 * cool);
      const ox = dx * push;
      const oy = dy * push;
      a.x -= ox;
      a.y -= oy;
      b.x += ox;
      b.y += oy;
    };
    for (const [key, list] of buckets) {
      const [cx0, cy0] = key.split(':').map(Number);
      for (let dx = 0; dx <= 1; dx++) {
        for (let dy = dx === 0 ? 0 : -1; dy <= 1; dy++) {
          const other = dx === 0 && dy === 0 ? list : buckets.get(`${cx0 + dx}:${cy0 + dy}`);
          if (!other) continue;
          if (other === list) {
            for (let i = 0; i < list.length; i++) {
              for (let j = i + 1; j < list.length; j++) collide(list[i], list[j]);
            }
          } else {
            for (const i of list) {
              for (const j of other) collide(i, j);
            }
          }
        }
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

/**
 * Lattice chords: k-nearest neighbors among co-members of an owner tag.
 * Co-membership ≠ trust — these are authored group filaments, not bonds.
 */
export function latticeChords(
  contacts: Array<{ peer_fingerprint: string; tags?: string[] }>,
  positions: Map<string, { x: number; y: number }>,
  k = 2,
): Array<{ a: string; b: string; tag: string }> {
  const byTag = tagMembership(contacts);
  const out: Array<{ a: string; b: string; tag: string }> = [];
  const seen = new Set<string>();
  for (const [tag, ids] of byTag) {
    if (ids.length < 2) continue;
    for (const id of ids) {
      const p = positions.get(id);
      if (!p) continue;
      const others = ids
        .filter((o) => o !== id)
        .map((o) => {
          const q = positions.get(o);
          const d = q ? Math.hypot(q.x - p.x, q.y - p.y) : Infinity;
          return { o, d };
        })
        .sort((a, b) => a.d - b.d)
        .slice(0, k);
      for (const { o } of others) {
        const key = [id, o].sort().join('|') + '|' + tag;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ a: id, b: o, tag });
      }
    }
  }
  return out;
}

/** Andrew's monotone chain — for faint Browse hulls. */
export function convexHull(
  pts: Array<{ x: number; y: number }>,
): Array<{ x: number; y: number }> {
  if (pts.length <= 2) return pts.slice();
  const p = [...pts].sort((a, b) => (a.x === b.x ? a.y - b.y : a.x - b.x));
  const cross = (
    o: { x: number; y: number },
    a: { x: number; y: number },
    b: { x: number; y: number },
  ) => (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lower: Array<{ x: number; y: number }> = [];
  for (const pt of p) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], pt) <= 0) {
      lower.pop();
    }
    lower.push(pt);
  }
  const upper: Array<{ x: number; y: number }> = [];
  for (let i = p.length - 1; i >= 0; i--) {
    const pt = p[i];
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], pt) <= 0) {
      upper.pop();
    }
    upper.push(pt);
  }
  lower.pop();
  upper.pop();
  return lower.concat(upper);
}
