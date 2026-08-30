/**
 * Browse-mode cluster layout for the Social Graph.
 * Owner-authored group tags → soft hulls of seal-dots.
 * Non-egocentric: no “you” hub — clusters float on their own.
 * Trust / known / mutual are node properties (witnessed on YOUR edges),
 * never inferred peer↔peer bonds. Co-membership ≠ trust.
 */

import type { TrustEdge } from '@/lib/trust/types';
import {
  assignConcentricSlots,
  radiusForCount,
  relaxGraphNodes,
} from '@/lib/trust/graph-forces';

export type BrowseMember = {
  id: string;
  fingerprint: string;
  name: string;
  /** Binary vouch — from your edge, not a score. */
  trusted: boolean;
  /** Witnessed reciprocal with you (mutual.reciprocal). */
  mutual: boolean;
  x: number;
  y: number;
};

export type BrowseCluster = {
  tag: string;
  cx: number;
  cy: number;
  r: number;
  members: BrowseMember[];
  trustedCount: number;
  knownCount: number;
  mutualCount: number;
};

function hashTag(tag: string): number {
  let h = 2166136261;
  for (let i = 0; i < tag.length; i++) {
    h ^= tag.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/**
 * Pack members around a centroid: trusted on an inner ring, known on an outer
 * ring so trust/know reads spatially without an egocentric hub.
 */
function placeMembers(
  tag: string,
  cx: number,
  cy: number,
  edges: TrustEdge[],
): { members: BrowseMember[]; r: number } {
  const trusted = edges.filter((e) => !!e.trusted);
  const known = edges.filter((e) => !e.trusted);
  const n = edges.length;

  const placeRing = (
    list: TrustEdge[],
    minR: number,
    maxR: number,
    startHash: number,
  ): BrowseMember[] => {
    const m = list.length;
    if (m === 0) return [];
    if (m === 1 && list === trusted && known.length === 0) {
      const e = list[0];
      return [
        {
          id: e.peer_fingerprint,
          fingerprint: e.peer_fingerprint,
          name: e.peer_name || 'Unnamed',
          trusted: !!e.trusted,
          mutual: !!e.mutual?.reciprocal,
          x: cx,
          y: cy,
        },
      ];
    }
    // Spill onto concentric rings when a single circle would stack seals.
    const maxPerRing = Math.max(5, Math.floor((2 * Math.PI * maxR) / 26));
    const slots = assignConcentricSlots(m, maxPerRing);
    const ringCount = 1 + Math.max(0, ...slots.map((s) => s.ring));
    return list.map((e, i) => {
      const slot = slots[i];
      const t = ringCount <= 1 ? 0 : slot.ring / (ringCount - 1);
      const baseR = minR + (maxR - minR) * t;
      const r =
        m === 1
          ? Math.min(baseR * 0.35, 16)
          : radiusForCount(slot.onRing, Math.max(12, baseR * 0.85), maxR, 26);
      const angle =
        (slot.index / Math.max(slot.onRing, 1)) * Math.PI * 2 -
        Math.PI / 2 +
        ((hashTag(tag) + startHash) % 17) * 0.01 +
        slot.ring * 0.09;
      return {
        id: e.peer_fingerprint,
        fingerprint: e.peer_fingerprint,
        name: e.peer_name || 'Unnamed',
        trusted: !!e.trusted,
        mutual: !!e.mutual?.reciprocal,
        x: cx + Math.cos(angle) * r,
        y: cy + Math.sin(angle) * r,
      };
    });
  };

  const innerMax = Math.max(20, 14 + trusted.length * 7);
  const innerMin = Math.max(14, innerMax * 0.7);
  const outerMin = Math.max(innerMax + 20, 26 + known.length * 5);
  const outerMax = Math.max(outerMin + 12, 32 + known.length * 8 + (trusted.length > 0 ? 8 : 0));

  let members = [
    ...placeRing(trusted, innerMin, innerMax, 3),
    ...placeRing(known, outerMin, outerMax, 11),
  ];

  // Local spacing pass inside the cluster so seals don't stack.
  if (members.length > 1) {
    const relaxed = relaxGraphNodes(
      members.map((m) => ({ id: m.id, x: m.x, y: m.y, radius: 7 })),
      {
        width: cx * 2 + 200,
        height: cy * 2 + 200,
        cx,
        cy,
        preferredRadius: new Map(
          members.map((m) => [m.id, Math.hypot(m.x - cx, m.y - cy) || 12]),
        ),
        padding: 12,
        selfClearance: 8,
        iterations: 28,
        ringGravity: 0.28,
        clusterGravity: 0,
        repulsion: 0.7,
        margin: 4,
      },
    );
    const byId = new Map(relaxed.map((r) => [r.id, r]));
    members = members.map((m) => {
      const r = byId.get(m.id);
      return r ? { ...m, x: r.x, y: r.y } : m;
    });
  }

  let maxDist = 0;
  for (const m of members) {
    maxDist = Math.max(maxDist, Math.hypot(m.x - cx, m.y - cy));
  }
  const hullR = Math.max(maxDist + 16, 32 + n * 4.5);
  return { members, r: hullR };
}

/**
 * Group contacts by first tag (Ungrouped if none). Layout cluster centroids
 * on a soft ring — no self at center.
 */
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

  // Seed members at provisional centroids, sized first so orbit can clear hulls.
  const seeded = tags.map((tag) => {
    const edges = buckets.get(tag) || [];
    const { members, r } = placeMembers(tag, 0, 0, edges);
    return { tag, members, r: r + 12, edges };
  });

  // Orbit radius grows with cluster count + average hull so groups don't overlap.
  const avgR =
    seeded.reduce((s, c) => s + c.r, 0) / Math.max(seeded.length, 1);
  const minOrbit =
    count <= 1 ? 0 : avgR + 36 + Math.min(40, count * 4);
  const maxOrbit = Math.min(width, height) * 0.42;
  const orbit = Math.min(maxOrbit, Math.max(minOrbit, Math.min(width, height) * (count <= 3 ? 0.28 : 0.34)));

  let clusters: BrowseCluster[] = seeded.map((seed, i) => {
    const angle = count === 1 ? -Math.PI / 8 : (i / count) * Math.PI * 2 - Math.PI / 2;
    const jitter = ((hashTag(seed.tag) % 100) / 100 - 0.5) * 10;
    const cx = count === 1 ? cx0 : cx0 + Math.cos(angle) * orbit + jitter;
    const cy = count === 1 ? cy0 : cy0 + Math.sin(angle) * orbit + jitter * 0.5;
    // Re-place members around the final centroid
    const { members, r } = placeMembers(seed.tag, cx, cy, seed.edges);
    const trustedCount = members.filter((m) => m.trusted).length;
    const mutualCount = members.filter((m) => m.mutual).length;
    return {
      tag: seed.tag,
      cx,
      cy,
      r: r + 10,
      members,
      trustedCount,
      knownCount: members.length - trustedCount,
      mutualCount,
    };
  });

  // Hull–hull repulsion so Browse clusters breathe apart.
  if (clusters.length > 1) {
    for (let iter = 0; iter < 36; iter++) {
      const cool = 1 - iter / 36;
      for (let i = 0; i < clusters.length; i++) {
        for (let j = i + 1; j < clusters.length; j++) {
          const a = clusters[i];
          const b = clusters[j];
          let dx = b.cx - a.cx;
          let dy = b.cy - a.cy;
          let dist = Math.hypot(dx, dy);
          const minDist = a.r + b.r + 18;
          if (dist < 1e-6) {
            const ang = (i * 2.4 + j) % (Math.PI * 2);
            dx = Math.cos(ang);
            dy = Math.sin(ang);
            dist = 1e-6;
          }
          if (dist >= minDist) continue;
          const push = ((minDist - dist) / dist) * 0.45 * cool;
          const ox = dx * push;
          const oy = dy * push;
          a.cx -= ox;
          a.cy -= oy;
          b.cx += ox;
          b.cy += oy;
        }
      }
      // Keep hulls inside the frame
      for (const cl of clusters) {
        const m = cl.r + 8;
        cl.cx = Math.min(width - m, Math.max(m, cl.cx));
        cl.cy = Math.min(height - m, Math.max(m, cl.cy));
      }
    }
    // Re-anchor members to nudged centroids (preserve relative offsets)
    clusters = clusters.map((cl, i) => {
      const prev = seeded[i];
      const { members, r } = placeMembers(cl.tag, cl.cx, cl.cy, prev.edges);
      return {
        ...cl,
        members,
        r: r + 10,
        trustedCount: members.filter((m) => m.trusted).length,
        knownCount: members.length - members.filter((m) => m.trusted).length,
        mutualCount: members.filter((m) => m.mutual).length,
      };
    });
  }

  return clusters;
}

/** All distinct tags across contacts (sorted). */
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
