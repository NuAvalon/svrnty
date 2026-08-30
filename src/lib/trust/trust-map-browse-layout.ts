/**
 * Browse-mode cluster layout for the Social Graph.
 * Owner-authored group tags → soft hulls of seal-dots.
 * Non-egocentric: no “you” hub — clusters float on their own.
 * Trust / known / mutual are node properties (witnessed on YOUR edges),
 * never inferred peer↔peer bonds. Co-membership ≠ trust.
 */

import type { TrustEdge } from '@/lib/trust/types';

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
  const innerR = Math.max(16, 10 + trusted.length * 5.5);
  const outerR = Math.max(innerR + 16, 22 + known.length * 6.5 + (trusted.length > 0 ? 8 : 0));
  const hullR = Math.max(outerR + 12, 28 + n * 5);

  const placeRing = (list: TrustEdge[], ringR: number, startHash: number): BrowseMember[] => {
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
    return list.map((e, i) => {
      const angle =
        (i / Math.max(m, 1)) * Math.PI * 2 -
        Math.PI / 2 +
        ((hashTag(tag) + startHash) % 17) * 0.01;
      const dist = m === 1 ? Math.min(ringR * 0.35, 14) : ringR;
      return {
        id: e.peer_fingerprint,
        fingerprint: e.peer_fingerprint,
        name: e.peer_name || 'Unnamed',
        trusted: !!e.trusted,
        mutual: !!e.mutual?.reciprocal,
        x: cx + Math.cos(angle) * dist,
        y: cy + Math.sin(angle) * dist,
      };
    });
  };

  const members = [
    ...placeRing(trusted, Math.min(innerR, outerR * 0.55), 3),
    ...placeRing(known, outerR * 0.72, 11),
  ];
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
  const orbit = Math.min(width, height) * (count <= 1 ? 0 : count <= 3 ? 0.26 : 0.3);

  return tags.map((tag, i) => {
    const angle = count === 1 ? -Math.PI / 8 : (i / count) * Math.PI * 2 - Math.PI / 2;
    const jitter = ((hashTag(tag) % 100) / 100 - 0.5) * 14;
    const cx = count === 1 ? cx0 : cx0 + Math.cos(angle) * orbit + jitter;
    const cy = count === 1 ? cy0 : cy0 + Math.sin(angle) * orbit + jitter * 0.55;
    const edges = buckets.get(tag) || [];
    const { members, r } = placeMembers(tag, cx, cy, edges);
    const trustedCount = members.filter((m) => m.trusted).length;
    const mutualCount = members.filter((m) => m.mutual).length;
    return {
      tag,
      cx,
      cy,
      r: r + 10,
      members,
      trustedCount,
      knownCount: members.length - trustedCount,
      mutualCount,
    };
  });
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
