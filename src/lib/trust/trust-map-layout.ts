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
//   Peer↔peer trust chords are NOT layout — the renderer overlays witnessed
  open-visibility filaments. Unlit = privacy, never absence.

import { isDecayed, daysUntilDecay } from './types';
import type { TrustEdge } from './types';
import { relaxGraphNodes, seedEgocentric, tagMembership } from './graph-forces';

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

export function worldSizeForCount(n: number): number {
  return Math.max(640, Math.round(180 + Math.sqrt(Math.max(n, 1)) * 58));
}

/** Salience — visual overlay, not orbital distance. */
export const NODE_RADIUS: Record<TrustState, number> = {
  trusted: 10,
  known: 7,
  decayed: 6,
};

export const SELF_CORE_RADIUS = 14;
export const SELF_RING_RADIUS = 22;

const EDGE_OPACITY: Record<TrustState, number> = {
  trusted: 0.62,
  known: 0.28,
  decayed: 0.14,
};

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
  const spread = Math.min(maxExtent * 0.88, 48 + Math.sqrt(Math.max(n, 1)) * 38);
  const minR = SELF_RING_RADIUS + 52;

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

  const relaxed = relaxGraphNodes(raw, {
    width,
    height,
    cx,
    cy,
    tagMembers: tagMembership(contacts),
    padding: 22,
    selfClearance: SELF_RING_RADIUS + 14,
    iterations: 56,
    clusterGravity: 0.2,
    centerGravity: 0.006,
    cloudMin: minR * 0.65,
    cloudMax: maxExtent * 0.94,
    repulsion: 0.78,
    margin: 18,
  });

  let cloudRadius = SELF_RING_RADIUS;
  for (const n of relaxed) {
    cloudRadius = Math.max(cloudRadius, Math.hypot(n.x - cx, n.y - cy) + n.radius);
  }

  return { width, height, cx, cy, self, nodes: relaxed, cloudRadius };
}
