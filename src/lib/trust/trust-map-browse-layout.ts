/**
 * Browse-mode cluster layout for the Social Graph.
 * Owner-authored group tags → soft hulls of seal-dots.
 * No inferred peer↔peer edges — co-membership ≠ trust.
 */

import type { TrustEdge } from '@/lib/trust/types';

export type BrowseMember = {
  id: string;
  fingerprint: string;
  name: string;
  trusted: boolean;
  x: number;
  y: number;
};

export type BrowseCluster = {
  tag: string;
  cx: number;
  cy: number;
  r: number;
  members: BrowseMember[];
};

function hashTag(tag: string): number {
  let h = 2166136261;
  for (let i = 0; i < tag.length; i++) {
    h ^= tag.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** Pack members in a small ring around a centroid. */
function placeMembers(
  tag: string,
  cx: number,
  cy: number,
  edges: TrustEdge[],
): { members: BrowseMember[]; r: number } {
  const n = edges.length;
  const r = Math.max(28, 18 + n * 7);
  const members: BrowseMember[] = edges.map((e, i) => {
    const angle = (i / Math.max(n, 1)) * Math.PI * 2 - Math.PI / 2 + (hashTag(tag) % 17) * 0.01;
    const dist = n === 1 ? 0 : Math.min(r - 14, 22 + n * 2.2);
    return {
      id: e.peer_fingerprint,
      fingerprint: e.peer_fingerprint,
      name: e.peer_name || 'Unnamed',
      trusted: !!e.trusted,
      x: cx + Math.cos(angle) * dist,
      y: cy + Math.sin(angle) * dist,
    };
  });
  return { members, r };
}

/**
 * Group contacts by first tag (Ungrouped if none). Layout cluster centroids
 * on a soft ring / grid inside the view.
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
  const orbit = Math.min(width, height) * (count <= 1 ? 0 : count <= 3 ? 0.22 : 0.28);

  return tags.map((tag, i) => {
    const angle = count === 1 ? 0 : (i / count) * Math.PI * 2 - Math.PI / 2;
    const jitter = ((hashTag(tag) % 100) / 100 - 0.5) * 12;
    const cx = cx0 + Math.cos(angle) * orbit + jitter;
    const cy = cy0 + Math.sin(angle) * orbit + jitter * 0.6;
    const edges = buckets.get(tag) || [];
    const { members, r } = placeMembers(tag, cx, cy, edges);
    return { tag, cx, cy, r: r + 10, members };
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
