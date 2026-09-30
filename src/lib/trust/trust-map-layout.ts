// src/lib/trust/trust-map-layout.ts
// Pure layout for the crystalline trust-map (flat SVG, mobile-first).
//
// Egocentric PARTICLE LATTICE — you at center, contacts in organic
// neighborhoods (owner-authored tags). Trust is NOT a radius from self;
// it is a visual overlay (glow / filament) applied by the renderer.
//
// WHY THIS FILE EXISTS (separately from the renderer):
//   The old TrustMap used a <canvas> with ABSOLUTE pixel radii that pushed
//   nodes off-screen on a phone. This module computes positions in a fixed
//   world and GUARANTEES (see tests) that every node lands inside the world
//   box. The camera (viewBox) then frames that world without CSS-scaling a
//   tiny bitmap.
//
// I-6 RENDER PROVENANCE:
//     • position     → I added this contact + optional owner-local tag neighborhood
//     • radius       → salience of the standing I granted (trusted > known) — overlay
//     • opacity      → what THEY disclosed to me
//   Peer↔peer trust chords ARE soft layout springs when witnessed
//   (open-visibility they_trust) — same fail-closed set as filaments.
//   Unlit / unwitnessed = privacy, never absence; tags never invent bonds.

import { isDecayed, daysUntilDecay } from './types';
import type { TrustEdge } from './types';
import { relaxGraphNodes, seedEgocentric, tagMembership } from './graph-forces';
import { witnessedPeerTrustChords } from './peer-trust-chords';

export type TrustState = 'trusted' | 'known' | 'decayed';

export interface LaidOutNode {
  id: string;
  name: string;
  state: TrustState;
  isOwner: boolean;
  x: number;
  y: number;
  radius: number;
  opacity: number;
  edgeOpacity: number;
  daysLeft: number;
}

export interface TrustLayout {
  width: number;
  height: number;
  cx: number;
  cy: number;
  self: LaidOutNode;
  nodes: LaidOutNode[];
  /** Soft cloud extent (not a drawn ring). */
  cloudRadius: number;
}

export type LayoutOptions = {
  width?: number;
  height?: number;
  /** Extra margin reserved for labels near the frame edge. */
  labelMargin?: number;
};

export function worldSizeForCount(n: number): number {
  // Grow world with √n so ~80–200 contacts get room to breathe (labels + seals).
  return Math.max(720, Math.round(220 + Math.sqrt(Math.max(n, 1)) * 72));
}

/** Salience — visual overlay, not orbital distance. Hex circumradius. */
export const NODE_RADIUS: Record<TrustState, number> = {
  trusted: 11,
  known: 8,
  decayed: 7,
};

export const SELF_CORE_RADIUS = 18;
export const SELF_RING_RADIUS = 28;

const EDGE_OPACITY: Record<TrustState, number> = {
  trusted: 0.88,
  known: 0.42,
  decayed: 0.16,
};

/**
 * Pointy-top hexagon vertices (SVG polygon points).
 * Circumradius `r` so collision/hit-test circles still wrap the cell.
 */
export function hexagonPoints(cx: number, cy: number, r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 6; i++) {
    const a = -Math.PI / 2 + (i * Math.PI) / 3;
    pts.push(`${+(cx + r * Math.cos(a)).toFixed(2)},${+(cy + r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(' ');
}

export function trustStateOf(edge: TrustEdge): TrustState {
  if (edge.trusted && isDecayed(edge)) return 'decayed';
  if (edge.trusted) return 'trusted';
  return 'known';
}

/**
 * DISCLOSURE DEPTH → node opacity [0.4..1].
 * Decodes ONLY to what the peer disclosed / what I witnessed.
 */
export function disclosureDepth(edge: TrustEdge): number {
  let d = 0.4;
  const ci = edge.contact_info;
  const hasChannel = !!ci && (
    (ci.phones?.length ?? 0) > 0 ||
    (ci.emails?.length ?? 0) > 0 ||
    (ci.urls?.length ?? 0) > 0 ||
    (!!ci.handles && Object.keys(ci.handles).length > 0)
  );
  if (hasChannel) d += 0.3;
  const verified =
    !!edge.verification &&
    edge.verification.method !== 'none' &&
    !!edge.verification.verified_at;
  if (verified) d += 0.3;
  return Math.min(d, 1);
}

/**
 * Compute node positions inside a fixed world.
 *
 * INVARIANT: every node center ± radius stays inside [0, width] × [0, height].
 * Trust does NOT determine distance from self.
 */
export function computeTrustLayout(
  ownerFingerprint: string,
  ownerName: string,
  contacts: TrustEdge[],
  opts: LayoutOptions = {},
): TrustLayout {
  const width = opts.width ?? 640;
  const height = opts.height ?? 640;
  const labelMargin = opts.labelMargin ?? 16;
  const cx = width / 2;
  const cy = height / 2;

  const self: LaidOutNode = {
    id: ownerFingerprint || 'self',
    name: ownerName || 'You',
    state: 'trusted',
    isOwner: true,
    x: cx,
    y: cy,
    radius: SELF_CORE_RADIUS,
    opacity: 1,
    edgeOpacity: 0,
    daysLeft: 0,
  };

  const n = contacts.length;
  const maxExtent = Math.min(cx, cy) - NODE_RADIUS.trusted - labelMargin - 8;
  const spread = Math.min(maxExtent * 0.92, 64 + Math.sqrt(Math.max(n, 1)) * 46);
  const minR = SELF_RING_RADIUS + 64;

  const seeds = seedEgocentric(
    contacts.map((c) => ({ id: c.peer_fingerprint, tags: c.tags })),
    cx,
    cy,
    minR,
    spread,
  );
  const seedById = new Map(seeds.map((s) => [s.id, s]));

  const raw: LaidOutNode[] = contacts.map((edge) => {
    const state = trustStateOf(edge);
    const seed = seedById.get(edge.peer_fingerprint);
    return {
      id: edge.peer_fingerprint,
      name: edge.peer_name,
      state,
      isOwner: false,
      x: seed?.x ?? cx,
      y: seed?.y ?? cy,
      radius: NODE_RADIUS[state],
      opacity: disclosureDepth(edge),
      edgeOpacity: EDGE_OPACITY[state],
      daysLeft: state === 'trusted' ? daysUntilDecay(edge) : 0,
    };
  });

  // Density-aware spacing: more contacts → more padding / repulsion / iterations.
  // First pass is a seed — TrustMap re-relaxes after layout memory, so keep this cheap.
  const density = Math.sqrt(Math.max(n, 1));
  const pad = Math.min(38, Math.round(18 + density * 1.8));
  const mutualBonds = witnessedPeerTrustChords(contacts).map((c) => ({
    a: c.a,
    b: c.b,
  }));
  const relaxed = relaxGraphNodes(raw, {
    width,
    height,
    cx,
    cy,
    tagMembers: tagMembership(contacts),
    mutualBonds,
    mutualBondGravity: 0.18,
    mutualBondRest: Math.max(58, NODE_RADIUS.trusted * 6),
    padding: pad,
    selfClearance: SELF_RING_RADIUS + 20,
    iterations: Math.min(64, 32 + Math.floor(n / 4)),
    clusterGravity: 0.16,
    centerGravity: 0.006,
    cloudMin: minR * 0.7,
    cloudMax: maxExtent * 0.96,
    repulsion: Math.min(1.2, 0.74 + density * 0.04),
    margin: 22,
  });

  let cloudRadius = SELF_RING_RADIUS;
  for (const n of relaxed) {
    cloudRadius = Math.max(cloudRadius, Math.hypot(n.x - cx, n.y - cy) + n.radius);
  }

  return { width, height, cx, cy, self, nodes: relaxed, cloudRadius };
}
