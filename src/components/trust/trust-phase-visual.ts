/**
 * Single-source trust-phase → visual map (render-glass).
 *
 * ALL bond paints (TrustMap SVG, TrustMapGalaxy canvas, MasterAddressBookList,
 * ContactManagement badge) read THIS map. Trust phase comes from
 * `livingEdgeStatus(edge).trust` — this file never recomputes trust from
 * `edge.trusted` / `edge.mutual`.
 *
 * WHITE / LIT if and only if `trust === 'mutual'`.
 */

import {
  livingEdgeStatus,
  type LivingConnectionPhase,
  type LivingEdgeStatus,
  type LivingTrustPhase,
} from '@/lib/trust/living-edge-status';
import type { TrustEdge } from '@/lib/trust/types';

export type TrustBondState =
  | 'known'
  | 'trust-sent'
  | 'trust-received'
  | 'mutual'
  | 'blocked';

export type TrustBondShape =
  | 'outline'
  | 'dashed-hollow'
  | 'half-filled'
  | 'solid-filled'
  | 'struck';

/** Spoke paint. One-way is a dual thin pair — never a dash, never the mutual glow. */
export type TrustSpokeStyle = 'single' | 'dual-thin' | 'thick-bright';

export const TRUST_VISUAL_LABELS = {
  known: 'Known',
  'trust-sent': 'Awaiting mutual',
  'trust-received': 'Trusts you · trust back?',
  mutual: 'Mutual',
  blocked: 'Blocked',
  introPending: 'Pending intro',
} as const;

/** Cream-white core — mutual bonds only. Never paint this on outbound. */
export const TRUST_VISUAL_WHITE_CORE = '#fffef8';
export const TRUST_VISUAL_WHITE_HALO = '#fff8ee';
export const TRUST_VISUAL_WHITE_SPOKE = '#fff6e8';

const MUTED_STROKE = '#8f7550';
const MUTED_FILL = 'rgba(143,117,80,0.10)';
const INBOUND_STROKE = '#f9a825';
const MUTUAL_FILL = 'color-mix(in srgb, var(--se-accent2) 22%, var(--se-bg))';
const MUTUAL_CANVAS_FILL = 'rgba(255,122,26,0.55)';
const KNOWN_STROKE = 'rgba(249,168,37,0.55)';
const BLOCKED_STROKE = 'rgba(143,117,80,0.45)';

/** Intro-handshake dash — connection axis only. One-way trust is never dashed. */
export const INTRO_PENDING_DASH = '3 2';
/** Half-hex fill for one-way (not a flowing core). */
export const ONE_WAY_HALF_FILL = 'rgba(143,117,80,0.42)';
export const ONE_WAY_INBOUND_HALF_FILL = 'rgba(249,168,37,0.40)';
export const ONE_WAY_SPOKE_WIDTH = 0.85;

export type TrustPhaseVisual = {
  bondState: TrustBondState;
  connection: LivingConnectionPhase;
  /** Bond-phase label (or Blocked / Pending intro when those axes win). */
  label: string;
  /** True IFF mutual. The only white/lit bond. */
  lit: boolean;
  white: boolean;
  shape: TrustBondShape;
  /** Intro handshake (connection axis) — never aliased as trust-sent. */
  introPending: boolean;
  verifiedMark: boolean;
  svgFill: string;
  svgStroke: string;
  svgStrokeWidth: number;
  svgDasharray: string | undefined;
  canvasFill: string | null;
  canvasStroke: string;
  canvasDash: number[] | null;
  coreFill: string | null;
  haloStroke: string | null;
  spokeStroke: string;
  spokeDasharray: string | undefined;
  spokeStyle: TrustSpokeStyle;
  spokeGlow: boolean;
  chipColorCss: string;
};

function bondStateOf(
  trust: LivingTrustPhase,
  blocked: boolean,
): TrustBondState {
  if (blocked) return 'blocked';
  if (trust === 'mutual') return 'mutual';
  if (trust === 'outbound') return 'trust-sent';
  if (trust === 'inbound') return 'trust-received';
  return 'known';
}

function displayLabel(
  bond: TrustBondState,
  introPending: boolean,
  trust: LivingTrustPhase,
): string {
  if (bond === 'blocked') return TRUST_VISUAL_LABELS.blocked;
  if (introPending && trust === 'none') return TRUST_VISUAL_LABELS.introPending;
  return TRUST_VISUAL_LABELS[bond];
}

const KNOWN_STATUS: LivingEdgeStatus = {
  connection: 'classical',
  trust: 'none',
  canCommunicate: false,
  methodDelivery: 'none',
  statusLine: 'Known',
  detailLine: null,
  lastMoment: null,
  decayFreshness: 1,
};

/**
 * Map a living-edge status onto paint tokens. Fail closed: missing/unknown
 * trust paints Known (outline, not lit).
 */
export function trustPhaseVisual(input: {
  status: LivingEdgeStatus;
  blocked?: boolean;
  verified?: boolean;
}): TrustPhaseVisual {
  const trust: LivingTrustPhase = input.status.trust;
  const introPending = input.status.connection === 'pending';
  const bond = bondStateOf(trust, input.blocked === true);
  const lit = bond === 'mutual';
  const label = displayLabel(bond, introPending, trust);

  if (bond === 'blocked') {
    return {
      bondState: bond,
      connection: input.status.connection,
      label,
      lit: false,
      white: false,
      shape: 'struck',
      introPending,
      verifiedMark: input.verified === true,
      svgFill: 'transparent',
      svgStroke: BLOCKED_STROKE,
      svgStrokeWidth: 1.05,
      svgDasharray: '2 3',
      canvasFill: null,
      canvasStroke: BLOCKED_STROKE,
      canvasDash: [2, 3],
      coreFill: null,
      haloStroke: null,
      spokeStroke: BLOCKED_STROKE,
      spokeDasharray: '2 3',
      spokeStyle: 'single',
      spokeGlow: false,
      chipColorCss: 'var(--se-danger)',
    };
  }

  if (bond === 'mutual') {
    return {
      bondState: bond,
      connection: input.status.connection,
      label,
      lit: true,
      white: true,
      shape: 'solid-filled',
      introPending,
      verifiedMark: input.verified === true,
      svgFill: MUTUAL_FILL,
      svgStroke: TRUST_VISUAL_WHITE_HALO,
      svgStrokeWidth: 1.85,
      svgDasharray: undefined,
      canvasFill: MUTUAL_CANVAS_FILL,
      canvasStroke: TRUST_VISUAL_WHITE_HALO,
      canvasDash: null,
      coreFill: TRUST_VISUAL_WHITE_CORE,
      haloStroke: TRUST_VISUAL_WHITE_HALO,
      spokeStroke: TRUST_VISUAL_WHITE_SPOKE,
      spokeDasharray: undefined,
      spokeStyle: 'thick-bright',
      spokeGlow: true,
      chipColorCss: 'var(--se-accent2)',
    };
  }

  if (bond === 'trust-sent') {
    return {
      bondState: bond,
      connection: input.status.connection,
      label,
      lit: false,
      white: false,
      shape: 'half-filled',
      introPending,
      verifiedMark: input.verified === true,
      svgFill: ONE_WAY_HALF_FILL,
      svgStroke: MUTED_STROKE,
      svgStrokeWidth: 1.25,
      svgDasharray: undefined,
      canvasFill: ONE_WAY_HALF_FILL,
      canvasStroke: MUTED_STROKE,
      canvasDash: null,
      coreFill: null,
      haloStroke: MUTED_STROKE,
      spokeStroke: MUTED_STROKE,
      spokeDasharray: undefined,
      spokeStyle: 'dual-thin',
      spokeGlow: false,
      chipColorCss: 'var(--se-muted)',
    };
  }

  if (bond === 'trust-received') {
    return {
      bondState: bond,
      connection: input.status.connection,
      label,
      lit: false,
      white: false,
      shape: 'half-filled',
      introPending,
      verifiedMark: input.verified === true,
      svgFill: ONE_WAY_INBOUND_HALF_FILL,
      svgStroke: INBOUND_STROKE,
      svgStrokeWidth: 1.25,
      svgDasharray: undefined,
      canvasFill: ONE_WAY_INBOUND_HALF_FILL,
      canvasStroke: INBOUND_STROKE,
      canvasDash: null,
      coreFill: null,
      haloStroke: INBOUND_STROKE,
      spokeStroke: INBOUND_STROKE,
      spokeDasharray: undefined,
      spokeStyle: 'dual-thin',
      spokeGlow: false,
      chipColorCss: 'var(--se-accent)',
    };
  }

  // Known (and intro-pending-with-no-trust): dim outline, no fill.
  const pendingIntroPaint = introPending && trust === 'none';
  return {
    bondState: 'known',
    connection: input.status.connection,
    label,
    lit: false,
    white: false,
    shape: pendingIntroPaint ? 'dashed-hollow' : 'outline',
    introPending,
    verifiedMark: input.verified === true,
    svgFill: pendingIntroPaint ? 'transparent' : MUTED_FILL,
    svgStroke: pendingIntroPaint ? '#f9a825' : KNOWN_STROKE,
    svgStrokeWidth: pendingIntroPaint ? 1.4 : 1.05,
    svgDasharray: pendingIntroPaint ? INTRO_PENDING_DASH : undefined,
    canvasFill: null,
    canvasStroke: pendingIntroPaint ? 'rgba(249,168,37,0.85)' : KNOWN_STROKE,
    canvasDash: pendingIntroPaint ? [3, 2] : null,
    coreFill: null,
    haloStroke: null,
    spokeStroke: pendingIntroPaint ? '#f9a825' : 'rgba(249,168,37,0.42)',
    spokeDasharray: pendingIntroPaint ? '5 4' : undefined,
    spokeStyle: 'single',
    spokeGlow: false,
    chipColorCss: pendingIntroPaint ? 'var(--se-accent)' : 'var(--se-dim)',
  };
}

/** Glass-pop / data-spoke lane. Intro pending stays `pending`; trust-sent is its own lane. */
export type TrustVisualLane =
  | 'pending'
  | 'known'
  | 'verified'
  | 'trust-sent'
  | 'trust-received'
  | 'mutual'
  | 'decayed'
  | 'blocked';

/** Read `livingEdgeStatus` (never recompute trust) then paint. Missing edge → Known. */
export function visualForEdge(
  edge: TrustEdge | null | undefined,
  extra?: { blocked?: boolean; verified?: boolean },
): TrustPhaseVisual {
  return trustPhaseVisual({
    status: edge ? livingEdgeStatus(edge) : KNOWN_STATUS,
    blocked: extra?.blocked,
    verified: extra?.verified,
  });
}

export function trustVisualLane(
  visual: TrustPhaseVisual,
  decayed: boolean,
): TrustVisualLane {
  if (visual.introPending && visual.bondState === 'known') return 'pending';
  if (visual.bondState === 'blocked') return 'blocked';
  if (decayed) return 'decayed';
  if (visual.bondState === 'mutual') return 'mutual';
  if (visual.bondState === 'trust-sent') return 'trust-sent';
  if (visual.bondState === 'trust-received') return 'trust-received';
  if (visual.verifiedMark) return 'verified';
  return 'known';
}
