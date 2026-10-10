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
  | 'broken'
  | 'blocked';

export type TrustBondShape =
  | 'outline'
  | 'dashed-hollow'
  | 'actionable'
  | 'solid-filled'
  | 'struck';

export const TRUST_VISUAL_LABELS = {
  known: 'Known',
  'trust-sent': 'Awaiting mutual',
  'trust-received': 'Trusts you · trust back?',
  'trust-received-again': 'One-way again · they still trust you',
  mutual: 'Mutual',
  broken: 'Trust broken',
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
const INBOUND_FILL = 'rgba(249,168,37,0.14)';
const MUTUAL_FILL = 'color-mix(in srgb, var(--se-accent2) 22%, var(--se-bg))';
const MUTUAL_CANVAS_FILL = 'rgba(255,122,26,0.55)';
const KNOWN_STROKE = 'rgba(249,168,37,0.55)';
const BLOCKED_STROKE = 'rgba(143,117,80,0.45)';

/** Intro-handshake dash — must not equal the trust-sent dash. */
export const INTRO_PENDING_DASH = '3 2';
/** Trust-sent (outbound, not yet mutual) dash. */
export const TRUST_SENT_DASH = '8 5';
/** Local break — dimmer and gappier than one-way pending. */
export const TRUST_BROKEN_DASH = '2 6';

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
  spokeGlow: boolean;
  chipColorCss: string;
};

function bondStateOf(
  trust: LivingTrustPhase,
  blocked: boolean,
  afterBreak: boolean,
): TrustBondState {
  if (blocked) return 'blocked';
  if (trust === 'mutual') return 'mutual';
  if (trust === 'outbound') return 'trust-sent';
  if (trust === 'inbound') return 'trust-received';
  if (afterBreak && trust === 'none') return 'broken';
  return 'known';
}

function displayLabel(
  bond: TrustBondState,
  introPending: boolean,
  trust: LivingTrustPhase,
  afterBreak: boolean,
): string {
  if (bond === 'blocked') return TRUST_VISUAL_LABELS.blocked;
  if (introPending && trust === 'none') return TRUST_VISUAL_LABELS.introPending;
  if (bond === 'trust-received' && afterBreak) return TRUST_VISUAL_LABELS['trust-received-again'];
  return TRUST_VISUAL_LABELS[bond];
}

/** Last owner-local trust_history action. Glass-only; never invents wire reciprocity. */
export function lastLocalTrustAction(
  edge: TrustEdge | null | undefined,
): 'trust' | 'break' | 'decay' | 'reverify' | null {
  const history = edge?.trust_history;
  if (!history || history.length === 0) return null;
  const action = history[history.length - 1]?.action;
  if (action === 'trust' || action === 'break' || action === 'decay' || action === 'reverify') {
    return action;
  }
  return null;
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
  /** Last local history action was break — paint broken / one-way-again. */
  afterBreak?: boolean;
}): TrustPhaseVisual {
  const trust: LivingTrustPhase = input.status.trust;
  const introPending = input.status.connection === 'pending';
  const afterBreak = input.afterBreak === true;
  const bond = bondStateOf(trust, input.blocked === true, afterBreak);
  const lit = bond === 'mutual';
  const label = displayLabel(bond, introPending, trust, afterBreak);

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
      spokeGlow: false,
      chipColorCss: 'var(--se-danger)',
    };
  }

  if (bond === 'broken') {
    return {
      bondState: bond,
      connection: input.status.connection,
      label,
      lit: false,
      white: false,
      shape: 'dashed-hollow',
      introPending,
      verifiedMark: input.verified === true,
      svgFill: 'transparent',
      svgStroke: BLOCKED_STROKE,
      svgStrokeWidth: 1.15,
      svgDasharray: TRUST_BROKEN_DASH,
      canvasFill: null,
      canvasStroke: BLOCKED_STROKE,
      canvasDash: [2, 6],
      coreFill: null,
      haloStroke: BLOCKED_STROKE,
      spokeStroke: BLOCKED_STROKE,
      spokeDasharray: TRUST_BROKEN_DASH,
      spokeGlow: false,
      chipColorCss: 'var(--se-dim)',
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
      shape: 'dashed-hollow',
      introPending,
      verifiedMark: input.verified === true,
      svgFill: 'transparent',
      svgStroke: MUTED_STROKE,
      svgStrokeWidth: 1.45,
      svgDasharray: TRUST_SENT_DASH,
      canvasFill: null,
      canvasStroke: MUTED_STROKE,
      canvasDash: [8, 5],
      coreFill: null,
      haloStroke: MUTED_STROKE,
      spokeStroke: MUTED_STROKE,
      spokeDasharray: TRUST_SENT_DASH,
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
      shape: 'actionable',
      introPending,
      verifiedMark: input.verified === true,
      svgFill: INBOUND_FILL,
      svgStroke: INBOUND_STROKE,
      svgStrokeWidth: 1.5,
      svgDasharray: undefined,
      canvasFill: INBOUND_FILL,
      canvasStroke: INBOUND_STROKE,
      canvasDash: null,
      coreFill: null,
      haloStroke: INBOUND_STROKE,
      spokeStroke: INBOUND_STROKE,
      spokeDasharray: undefined,
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
  | 'broken'
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
    afterBreak: lastLocalTrustAction(edge) === 'break',
  });
}

export function trustVisualLane(
  visual: TrustPhaseVisual,
  decayed: boolean,
): TrustVisualLane {
  if (visual.introPending && visual.bondState === 'known') return 'pending';
  if (visual.bondState === 'blocked') return 'blocked';
  if (visual.bondState === 'broken') return 'broken';
  if (decayed) return 'decayed';
  if (visual.bondState === 'mutual') return 'mutual';
  if (visual.bondState === 'trust-sent') return 'trust-sent';
  if (visual.bondState === 'trust-received') return 'trust-received';
  if (visual.verifiedMark) return 'verified';
  return 'known';
}
