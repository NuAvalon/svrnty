// src/lib/trust/book-view.ts
// 0.14 — the render-model for the two-sided living book.
//
// Pure, deterministic, React-free. It turns a set of TrustEdges + the states
// they held on the PREVIOUS render into the two-sided view: the LIVING side and
// the RESTING side (gray + dim), flags which contacts just ignited (gray/dim ->
// living), and hands back the state map to feed in on the next render.
//
// The one piece of real logic here — detecting an ignition ACROSS renders — is
// kept out of the component on purpose, so it can be unit-tested without a DOM
// (same split as the ceremony's machine.ts). The component stays a thin view.
//
// Like contact-state.ts, this reads TrustEdge as-is and stores nothing, so it
// never collides with the format/envelope foundation.

import type { TrustEdge } from './types';
import { daysUntilDecay } from './types';
import { getContactState, isBloomTransition, type ContactState } from './contact-state';

export interface BookRow {
  edge: TrustEdge;
  state: ContactState;
  /** Ignited into LIVING this render (gray/dim -> living). The UI blooms these. */
  blooming: boolean;
  /** Days until (re)decay — for living/dim (negative = already faded). null for gray. */
  daysUntilDecay: number | null;
}

export interface BookView {
  /** Vouched + fresh — the alive side. Freshest first. */
  living: BookRow[];
  /** gray (cards you hold) + dim (faded, will re-ignite). Gray first, then most-faded. */
  resting: BookRow[];
  /** ids that ignited into living this render. */
  bloomingIds: string[];
  /** state per edge id this render — pass back as prevStates on the next render. */
  states: Record<string, ContactState>;
}

/** Living side: freshest (most days-until-decay) first, then name for stability. */
function byFreshness(a: BookRow, b: BookRow): number {
  const da = a.daysUntilDecay ?? -Infinity;
  const db = b.daysUntilDecay ?? -Infinity;
  if (db !== da) return db - da;
  return a.edge.peer_name.localeCompare(b.edge.peer_name);
}

/** Resting side: gray (new cards to act on) before dim; within dim, most-faded first. */
function byRestOrder(a: BookRow, b: BookRow): number {
  if (a.state !== b.state) return a.state === 'gray' ? -1 : 1;
  if (a.state === 'dim') {
    const da = a.daysUntilDecay ?? 0; // both dim => both numbers; most-negative (most faded) leads
    const db = b.daysUntilDecay ?? 0;
    if (da !== db) return da - db;
  }
  return a.edge.peer_name.localeCompare(b.edge.peer_name);
}

/**
 * Build the two-sided book view.
 *
 * @param edges       the current trust edges.
 * @param prevStates  the state each edge held on the last render (id -> state).
 *                    Empty on first render — so nothing blooms on first paint.
 */
export function buildBookView(
  edges: TrustEdge[],
  prevStates: Record<string, ContactState> = {},
): BookView {
  const living: BookRow[] = [];
  const resting: BookRow[] = [];
  const bloomingIds: string[] = [];
  const states: Record<string, ContactState> = {};

  for (const edge of edges) {
    const state = getContactState(edge);
    const blooming = isBloomTransition(prevStates[edge.id], state);
    const row: BookRow = {
      edge,
      state,
      blooming,
      daysUntilDecay: edge.trusted ? daysUntilDecay(edge) : null,
    };
    states[edge.id] = state;
    if (blooming) bloomingIds.push(edge.id);
    (state === 'living' ? living : resting).push(row);
  }

  living.sort(byFreshness);
  resting.sort(byRestOrder);
  return { living, resting, bloomingIds, states };
}
