/**
 * Browse-mode cluster layout for the Social Graph.
 * Owner-authored group tags → organic neighborhoods (not concentric rings).
 * Non-egocentric: no “you” hub — clusters float on their own.
 * Trust / known / mutual are overlays on YOUR edges, never inferred bonds.
 */

import type { TrustEdge } from '@/lib/trust/types';
import {
  convexHull,
  hash32,
  relaxGraphNodes,
  seedPhyllotaxis,
} from '@/lib/trust/graph-forces';

export type BrowseMember = {
  id: string;
  fingerprint: string;
  name: string;
  trusted: boolean;
  mutual: boolean;
  x: number;
  y: number;
};

export type BrowseCluster = {
  tag: string;
  cx: number;
  cy: number;
  r: number;
  hull: Array<{ x: number; y: number }>;
  members: BrowseMember[];
};

function placeMembers(
  tag: string,
  cx: number,
  cy: number,
  edges: TrustEdge[],
): { members: BrowseMember[]; r: number; hull: Array<{ x: number; y: number }> } {
  const n = edges.length;
  if (n === 0) return { members: [], r: 28, hull: [] };

  if (n === 1) {
    const e = edges[0];
    const m: BrowseMember = {
      id: e.peer_fingerprint,
      fingerprint: e.peer_fingerprint,
      name: e.peer_name || 'Unnamed',
      trusted: !!e.trusted,
      mutual: !!e.mutual?.reciprocal,
      x: cx,
      y: cy,
    };
    return { members: [m], r: 26, hull: [{ x: cx, y: cy }] };
  }

  const spread = 18 + Math.sqrt(n) * 14;
  const seeds = seedPhyllotaxis(n, cx, cy, 12, spread, ((hash32(tag) % 360) * Math.PI) / 180);
  let members: BrowseMember[] = edges.map((e, i) => {
    const j = (hash32(e.peer_fingerprint) % 1000) / 1000;
    const s = seeds[i] ?? { x: cx, y: cy };
    return {
      id: e.peer_fingerprint,
      fingerprint: e.peer_fingerprint,
      name: e.peer_name || 'Unnamed',
      trusted: !!e.trusted,
      mutual: !!e.mutual?.reciprocal,
      x: s.x + (j - 0.5) * 10,
      y: s.y + (((hash32(e.peer_fingerprint + tag) % 1000) / 1000) - 0.5) * 10,
    };
  });

  const relaxed = relaxGraphNodes(
    members.map((m) => ({ id: m.id, x: m.x, y: m.y, radius: 7 })),
    {
      width: cx * 2 + 400,
      height: cy * 2 + 400,
      cx,
      cy,
      padding: 14,
      selfClearance: 4,
      iterations: 32,
      clusterGravity: 0,
      centerGravity: 0.06,
      cloudMin: 8,
      cloudMax: spread + 18,
      repulsion: 0.72,
      margin: 4,
    },
  );
  const byId = new Map(relaxed.map((r) => [r.id, r]));
  members = members.map((m) => {
    const r = byId.get(m.id);
    return r ? { ...m, x: r.x, y: r.y } : m;
  });

  let maxDist = 0;
  for (const m of members) {
    maxDist = Math.max(maxDist, Math.hypot(m.x - cx, m.y - cy));
  }
  const hull = convexHull(members.map((m) => ({ x: m.x, y: m.y })));
  return { members, r: Math.max(maxDist + 18, 28), hull };
}

export function computeBrowseClusters(
  contacts: TrustEdge[],
  width: number,
  height: number,
): BrowseCluster[] {
  const buckets = new Map<string, TrustEdge[]>();
  for (const c of contacts) {
    const tags = (c.tags || []).map((t) => t.trim()).filter(Boolean);
    const key = tags[0] || 'Ungrouped';
    const list = buckets.get(key) || [];
    list.push(c);
    buckets.set(key, list);
  }

  const tags = [...buckets.keys()].sort((a, b) => {
    if (a === 'Ungrouped') return 1;
    if (b === 'Ungrouped') return -1;
    return a.localeCompare(b);
  });

  const cx0 = width / 2;
  const cy0 = height / 2;
  const count = tags.length;

  const seeded = tags.map((tag) => {
    const edges = buckets.get(tag) || [];
    const placed = placeMembers(tag, 0, 0, edges);
    return { tag, ...placed, edges };
  });

  const avgR = seeded.reduce((s, c) => s + c.r, 0) / Math.max(seeded.length, 1);
  const minOrbit = count <= 1 ? 0 : avgR + 28 + Math.min(28, count * 3);
  const maxOrbit = Math.min(width, height) * 0.3;
  const orbit = Math.min(
    maxOrbit,
    Math.max(minOrbit, Math.min(width, height) * (count <= 3 ? 0.22 : 0.26)),
  );

  let clusters: BrowseCluster[] = seeded.map((seed, i) => {
    const angle = count === 1 ? -Math.PI / 8 : (i / count) * Math.PI * 2 - Math.PI / 2;
    const jitter = ((hash32(seed.tag) % 100) / 100 - 0.5) * 18;
    const cx = count === 1 ? cx0 : cx0 + Math.cos(angle) * orbit + jitter;
    const cy = count === 1 ? cy0 : cy0 + Math.sin(angle) * orbit + jitter * 0.45;
    const placed = placeMembers(seed.tag, cx, cy, seed.edges);
    return {
      tag: seed.tag,
      cx,
      cy,
      r: placed.r + 8,
      hull: placed.hull,
      members: placed.members,
    };
  });

  if (clusters.length > 1) {
    for (let iter = 0; iter < 40; iter++) {
      const cool = 1 - iter / 40;
      for (let i = 0; i < clusters.length; i++) {
        for (let j = i + 1; j < clusters.length; j++) {
          const a = clusters[i];
          const b = clusters[j];
          let dx = b.cx - a.cx;
          let dy = b.cy - a.cy;
          let dist = Math.hypot(dx, dy);
          const minDist = a.r + b.r + 22;
          if (dist < 1e-6) {
            const ang = (i * 2.4 + j) % (Math.PI * 2);
            dx = Math.cos(ang);
            dy = Math.sin(ang);
            dist = 1e-6;
          }
          if (dist >= minDist) continue;
          const push = ((minDist - dist) / dist) * 0.48 * cool;
          a.cx -= dx * push;
          a.cy -= dy * push;
          b.cx += dx * push;
          b.cy += dy * push;
        }
      }
      for (const cl of clusters) {
        const m = cl.r + 10;
        cl.cx = Math.min(width - m, Math.max(m, cl.cx));
        cl.cy = Math.min(height - m, Math.max(m, cl.cy));
      }
    }
    clusters = clusters.map((cl, i) => {
      const prev = seeded[i];
      const placed = placeMembers(cl.tag, cl.cx, cl.cy, prev.edges);
      return {
        ...cl,
        members: placed.members,
        hull: placed.hull,
        r: placed.r + 8,
      };
    });
  }

  return clusters;
}

export function collectGroupTags(contacts: TrustEdge[]): string[] {
  const set = new Set<string>();
  for (const c of contacts) {
    for (const t of c.tags || []) {
      const v = t.trim();
      if (v) set.add(v);
    }
  }
  return [...set].sort((a, b) => a.localeCompare(b));
}
