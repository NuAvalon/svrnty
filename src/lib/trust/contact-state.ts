// src/lib/trust/contact-state.ts
// 0.14 — the two-sided living address book: gray / living / DIM.
//
// A contact's "state" is DERIVED, never stored — a pure read over the existing
// TrustEdge trust + decay model. Because it adds no persisted field, it never
// collides with the format/envelope foundation: it reads TrustEdge as-is.
//
//   GRAY   — known but not trusted (!trusted). A card you hold; no live trust yet.
//   LIVING — trusted and fresh (trusted, within the decay window). Alive.
//   DIM    — trusted but faded (trusted, past the decay window). Not broken,
//            just gone quiet — re-ignites to LIVING on the next interaction.

import type { TrustEdge } from './types';
import { isDecayed } from './types';

export type ContactState = 'gray' | 'living' | 'dim';

/**
 * Derive a contact's state from its trust edge.
 *
 * Pure, deterministic, read-only. It leans entirely on the built-in decay clock
 * (trusted + last_interaction + decay_days, via isDecayed) — the SAME clock that
 * drives the graph — so any signal that refreshes last_interaction moves a
 * contact DIM -> LIVING with zero extra bookkeeping. No new stored field.
 */
export function getContactState(edge: TrustEdge): ContactState {
  if (!edge.trusted) return 'gray';
  return isDecayed(edge) ? 'dim' : 'living';
}

/**
 * The ignition bloom fires when a contact comes alive — GRAY or DIM -> LIVING.
 * The caller passes the previously-rendered state (undefined on first render);
 * the transition is tracked in the UI render layer, never persisted. First
 * render never blooms (there was no prior state to transition from).
 */
export function isBloomTransition(prev: ContactState | undefined, next: ContactState): boolean {
  return next === 'living' && (prev === 'gray' || prev === 'dim');
}

/** Display language for each state — the two-sided book's visual vocabulary. */
export const CONTACT_STATE_META: Record<ContactState, { label: string; hint: string }> = {
  gray:   { label: 'Gray',   hint: 'Known, not yet Trusted' },
  living: { label: 'Living', hint: 'Trusted and fresh' },
  dim:    { label: 'Dim',    hint: 'Trusted but faded — will re-ignite on contact' },
};

/**
 * Split a set of edges into the two sides of the book:
 * the LIVING side (alive, fresh) vs the RESTING side (gray + dim).
 * A neutral primitive for the two-sided render; the UI decides presentation.
 */
export function partitionBook(edges: TrustEdge[]): { living: TrustEdge[]; resting: TrustEdge[] } {
  const living: TrustEdge[] = [];
  const resting: TrustEdge[] = [];
  for (const e of edges) {
    (getContactState(e) === 'living' ? living : resting).push(e);
  }
  return { living, resting };
}
