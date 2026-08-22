// src/lib/trust/trust-map-layout.ts
// Pure layout for the crystalline trust-map (flat SVG, mobile-first).
//
// WHY THIS FILE EXISTS (separately from the renderer):
//   The old TrustMap used a <canvas> with ABSOLUTE pixel radii (trusted 130 /
//   known 280 / decayed 340). On a ~360px phone, half-width ≈180 < 280, so every
//   non-center node was placed OFF-CANVAS — "only the center shows." This module
//   computes positions in a fixed viewBox space and GUARANTEES (see tests) that
//   every node — for any contact count, any viewBox size — lands fully inside the
//   frame. The SVG then scales that frame to 100% width, so it can never overflow
//   the device. The mobile bug is killed at the layout layer, provably.
//
// I-6 RENDER PROVENANCE (svrnty vivre spec §3):
//   Every visual property this module emits decodes to something the viewer
//   AUTHORED or WITNESSED — nothing is inferred.
//     • position/edge  → I added this contact (a you→peer edge I formed).
//     • radius/salience → the trust standing I granted (trusted > known).
//     • opacity/depth   → what THEY disclosed to me (contact channels, proofs).
//   We deliberately do NOT emit peer↔peer edges ("clusters"/"bridges"): the data
//   has no peer-to-peer relation (`mutual` = does-this-peer-trust-ME, not
//   do-two-of-my-contacts-know-each-other). Rendering those would be inference.
//   Unlit = privacy, never absence.

import { isDecayed, daysUntilDecay } from './types';
import type { TrustEdge } from './types';

export type TrustState = 'trusted' | 'known' | 'decayed';

export interface LaidOutNode {
  id: string;          // peer_fingerprint (or owner fingerprint for self)
  name: string;        // display name the viewer gave them
  state: TrustState;
  isOwner: boolean;
  x: number;
  y: number;
  radius: number;      // SALIENCE — trust standing I granted
  opacity: number;     // DISCLOSURE DEPTH — what they've shared with me [0..1]
  edgeOpacity: number; // strength of my you→node edge [0..1]; 0 for self
  daysLeft: number;    // days until trust decays (trusted only; else 0)
}

export interface TrustLayout {
  width: number;
  height: number;
  cx: number;
  cy: number;
  self: LaidOutNode;
  nodes: LaidOutNode[];   // contacts only (self is separate)
  ringInner: number;      // radius of the trusted ring (for optional guide render)
  ringOuter: number;      // radius of the known/decayed ring
}

export interface LayoutOptions {
  width?: number;        // viewBox width  (default 400)
  height?: number;       // viewBox height (default 400)
  labelMargin?: number;  // vertical space reserved under a node for its label
}

// Node draw radii, in viewBox units. Salience: the standing I granted.
export const NODE_RADIUS: Record<TrustState, number> = {
  trusted: 9,
  known: 6,
  decayed: 5,
};

// Self node radii (the viewer, at center). Standing-ring is drawn by the renderer.
export const SELF_CORE_RADIUS = 13;
export const SELF_RING_RADIUS = 26;

// Strength of my you→node edge, by the standing I granted (authored).
const EDGE_OPACITY: Record<TrustState, number> = {
  trusted: 0.6,
  known: 0.25,
  decayed: 0.12,
};

/** Trust state of an edge — real, authored/witnessed state only. */
export function trustStateOf(edge: TrustEdge): TrustState {
  if (edge.trusted && isDecayed(edge)) return 'decayed';
  if (edge.trusted) return 'trusted';
  return 'known';
}

/**
 * DISCLOSURE DEPTH → node opacity [0.4..1].
 * Decodes ONLY to what the peer disclosed / what I witnessed:
 *   base 0.4 (the edge exists — I witnessed adding them)
 *   +0.3 if they shared any contact channel (phone/email/url/handle)
 *   +0.3 if a verification was actually proven
 * A known contact who shared nothing sits at 0.4 — the dim rim. Unlit = privacy.
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
 * Compute node positions inside a fixed viewBox.
 *
 * INVARIANT (unit-tested): for every node n,
 *   NODE_RADIUS <= n.x <= width  - NODE_RADIUS   (and same for y, plus labelMargin
 *   at the bottom). No node can escape the frame regardless of contact count or
 *   viewBox size. This is the structural fix for the mobile "only-center" bug.
 */
export function computeTrustLayout(
  ownerFingerprint: string,
  ownerName: string,
  contacts: TrustEdge[],
  opts: LayoutOptions = {},
): TrustLayout {
  const width = opts.width ?? 400;
  const height = opts.height ?? 400;
  const labelMargin = opts.labelMargin ?? 16;
  const cx = width / 2;
  const cy = height / 2;

  // Largest a node can be, incl. its label, so it stays inside the frame.
  const maxNodeExtent = NODE_RADIUS.trusted + labelMargin;
  // Safe ceiling for any ring radius: the closer wall minus a node's extent.
  const maxRing = Math.max(0, Math.min(cx, cy) - maxNodeExtent);
  const ringOuter = Math.min(150, maxRing);
  const ringInner = ringOuter * 0.63; // trusted sit closer in

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

  // Trusted (live) sit on the inner ring; known + decayed on the outer rim.
  const trusted: TrustEdge[] = [];
  const outer: TrustEdge[] = [];
  for (const c of contacts) {
    if (trustStateOf(c) === 'trusted') trusted.push(c);
    else outer.push(c);
  }

  const placeRing = (items: TrustEdge[], radius: number, angleOffset: number): LaidOutNode[] => {
    const n = items.length;
    return items.map((edge, i) => {
      // Deterministic even distribution, starting at the top. No randomness:
      // the layout is stable across renders (clean crystallization) and testable.
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(n, 1) + angleOffset;
      const state = trustStateOf(edge);
      return {
        id: edge.peer_fingerprint,
        name: edge.peer_name,
        state,
        isOwner: false,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        radius: NODE_RADIUS[state],
        opacity: disclosureDepth(edge),
        edgeOpacity: EDGE_OPACITY[state],
        daysLeft: state === 'trusted' ? daysUntilDecay(edge) : 0,
      };
    });
  };

  const nodes = [
    ...placeRing(trusted, ringInner, 0),
    // offset the outer ring half a step so nodes nest between inner spokes
    ...placeRing(outer, ringOuter, outer.length ? Math.PI / outer.length : 0),
  ];

  return { width, height, cx, cy, self, nodes, ringInner, ringOuter };
}
