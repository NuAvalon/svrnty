/**
 * Focus constellation — who lights up when you lamp one person.
 *
 * Everyone in the graph is already in YOUR book (you know them).
 * Lighting a neighbor is NOT "inferring a Facebook friendship."
 *
 * Allowed reasons (authored or witnessed):
 *   - shared-group     owner-local tags you wrote
 *   - disclosed-circle fingerprints they disclosed to you that are also in your book
 *                      (fleet `visible()` ∩ book — never computed here)
 *   - they-trust       open-visibility peer trust (Peter's spec): I trust both,
 *                      they trust me, we all opted in, and they_trust is witnessed
 *
 * Forbidden: inventing peer↔peer bonds from tags or friends-of-friends;
 *            mutual-friend counts as identity scores (I-3).
 */

import type { TrustEdge } from '@/lib/trust/types';
import { peerTrustNeighbors } from '@/lib/trust/peer-trust-chords';

export type ConstellationReason = 'shared-group' | 'disclosed-circle' | 'they-trust';

export type ConstellationMember = {
  id: string;
  reasons: ConstellationReason[];
  /** Owner tag when the link is a group you named. */
  tags: string[];
};

export type FocusConstellation = {
  focusId: string;
  members: Map<string, ConstellationMember>;
};

function extra(edge: TrustEdge): {
  mutual_contacts?: string[];
  disclosed_circle?: string[];
} {
  const e = edge as TrustEdge & {
    disclosed_circle?: string[];
    metadata?: {
      mutual_contacts?: string[];
      disclosed_circle?: string[];
    };
  };
  return {
    mutual_contacts: e.metadata?.mutual_contacts,
    disclosed_circle: e.disclosed_circle || e.metadata?.disclosed_circle,
  };
}

function add(
  map: Map<string, ConstellationMember>,
  id: string,
  reason: ConstellationReason,
  tag?: string,
) {
  if (!id) return;
  const cur = map.get(id) || { id, reasons: [], tags: [] };
  if (!cur.reasons.includes(reason)) cur.reasons.push(reason);
  if (tag && !cur.tags.includes(tag)) cur.tags.push(tag);
  map.set(id, cur);
}

/**
 * People around `focusId` that may light up. Focus themselves is omitted
 * (the lamp is already on). Unknown ids (not in the book) are dropped.
 */
export function focusConstellation(
  focusId: string,
  contacts: TrustEdge[],
): FocusConstellation {
  const members = new Map<string, ConstellationMember>();
  const inBook = new Set(contacts.map((c) => c.peer_fingerprint));
  const focus = contacts.find((c) => c.peer_fingerprint === focusId);
  if (!focus) return { focusId, members };

  const focusTags = new Set((focus.tags || []).map((t) => t.trim()).filter(Boolean));
  if (focusTags.size > 0) {
    for (const c of contacts) {
      if (c.peer_fingerprint === focusId) continue;
      const shared = (c.tags || []).filter((t) => focusTags.has(t));
      for (const tag of shared) add(members, c.peer_fingerprint, 'shared-group', tag);
    }
  }

  const x = extra(focus);
  const circle = [...(x.disclosed_circle || []), ...(x.mutual_contacts || [])];
  for (const fp of circle) {
    if (fp === focusId) continue;
    if (!inBook.has(fp)) continue;
    add(members, fp, 'disclosed-circle');
  }

  const bookByLower = new Map([...inBook].map((id) => [id.toLowerCase(), id]));
  for (const fp of peerTrustNeighbors(focusId, contacts)) {
    const bookId = inBook.has(fp) ? fp : bookByLower.get(fp.toLowerCase());
    if (!bookId || bookId === focusId) continue;
    add(members, bookId, 'they-trust');
  }

  return { focusId, members };
}

/** Honest HUD line — no mutual-friend counts, no inferred bonds. */
export function constellationCaption(c: FocusConstellation, focusTrusted: boolean): string {
  const n = c.members.size;
  if (n === 0) {
    return focusTrusted
      ? 'Your bond · no shared group or disclosed circle on this device'
      : 'Known · lamp them to see groups you named';
  }
  const hasCircle = [...c.members.values()].some((m) => m.reasons.includes('disclosed-circle'));
  const hasTrust = [...c.members.values()].some((m) => m.reasons.includes('they-trust'));
  const hasGroup = [...c.members.values()].some((m) => m.reasons.includes('shared-group'));
  const bits: string[] = [];
  if (hasGroup) bits.push('groups you named');
  if (hasCircle) bits.push('circle they showed you');
  if (hasTrust) bits.push('open-visibility peer trust · witnessed');
  return bits.join(' · ') || 'Your bond';
}
