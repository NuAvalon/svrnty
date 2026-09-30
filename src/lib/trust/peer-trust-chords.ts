/**
 * Witnessed peer↔peer trust chords — the open-visibility spec.
 *
 * If I trust Sally and Joe, they trust me, and we all have open visibility
 * for trusted contacts, I see that they trust each other (and they see that
 * I trust them). That is consented disclosure, not Facebook-style inference.
 *
 * Glass NEVER computes PSI. It only draws a chord when both edges already
 * carry `they_trust` / `peer_mutual` (fleet-filled or demo stand-in) AND
 * the local open-visibility + reciprocal-trust predicate holds. Co-membership
 * of an owner tag is not a bond.
 */

import type { TrustEdge } from '@/lib/trust/types';

export type WitnessedPeerChord = {
  a: string;
  b: string;
};

type ChordSource = TrustEdge & {
  open_visibility?: boolean;
  peer_mutual?: Array<{ peer_fingerprint: string }>;
  metadata?: {
    they_trust?: string[];
    share_settings?: { open_visibility?: boolean };
  };
};

function fpOf(c: TrustEdge): string {
  return (c.peer_fingerprint || '').toLowerCase();
}

function theyTrustSet(c: ChordSource): Set<string> {
  const ids = [
    ...(c.they_trust || []),
    ...(c.metadata?.they_trust || []),
    ...((c.peer_mutual || []).map((p) => p.peer_fingerprint)),
  ];
  return new Set(ids.map((id) => (id || '').toLowerCase()).filter(Boolean));
}

/** Owner opted in toward this peer (per-contact share setting — there is no book-global flag). */
export function ownerOpenVisibilityToward(c: ChordSource): boolean {
  return c.open_visibility === true || c.metadata?.share_settings?.open_visibility === true;
}

/**
 * Eligible for open-visibility peer chords with the owner:
 * trusted by me, they trust me, and I opened visibility toward them.
 */
export function isOpenVisibilityMutual(c: TrustEdge): boolean {
  if (!c.trusted) return false;
  const theyTrustMe = c.mutual?.reciprocal === true || c.mutual?.they_trust_me === true;
  if (!theyTrustMe) return false;
  return ownerOpenVisibilityToward(c as ChordSource);
}

/**
 * Undirected chords among people in MY book who mutually trust me, have
 * open visibility, and whose `they_trust` lists include each other.
 * Fail closed on one-way they_trust, missing open vis, or non-reciprocal.
 */
export function witnessedPeerTrustChords(contacts: TrustEdge[]): WitnessedPeerChord[] {
  const eligible = contacts.filter((c) => isOpenVisibilityMutual(c) && fpOf(c));
  const chords: WitnessedPeerChord[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < eligible.length; i++) {
    for (let j = i + 1; j < eligible.length; j++) {
      const A = eligible[i] as ChordSource;
      const B = eligible[j] as ChordSource;
      const af = fpOf(A);
      const bf = fpOf(B);
      if (!af || !bf || af === bf) continue;
      if (!theyTrustSet(A).has(bf) || !theyTrustSet(B).has(af)) continue;
      const key = af < bf ? `${af}|${bf}` : `${bf}|${af}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const [left, right] = af < bf ? [A, B] : [B, A];
      chords.push({ a: left.peer_fingerprint, b: right.peer_fingerprint });
    }
  }
  return chords;
}

function theyKnowSet(c: ChordSource): Set<string> {
  const extra = c as ChordSource & {
    disclosed_circle?: string[];
    metadata?: { disclosed_circle?: string[]; mutual_contacts?: string[] };
  };
  const ids = [
    ...(extra.disclosed_circle || []),
    ...(extra.metadata?.disclosed_circle || []),
    ...(extra.metadata?.mutual_contacts || []),
  ];
  return new Set(ids.map((id) => (id || '').toLowerCase()).filter(Boolean));
}

function isPendingStar(c: TrustEdge): boolean {
  const e = c as TrustEdge & { connection_status?: string; pending_intro?: unknown };
  return e.connection_status === 'pending' || !!e.pending_intro;
}

/**
 * Eligible for open-visibility Know chords with the owner:
 * in the book (Known), not pending, and I opened visibility toward them.
 * Trust is NOT required — Know ≠ Trust.
 */
export function isOpenVisibilityKnown(c: TrustEdge): boolean {
  if (isPendingStar(c)) return false;
  if (!fpOf(c)) return false;
  return ownerOpenVisibilityToward(c as ChordSource);
}

function chordKey(a: string, b: string): string {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  return x < y ? `${x}|${y}` : `${y}|${x}`;
}

export type WitnessedPeerLayer = 'know' | 'trust';

export type LayeredPeerChord = WitnessedPeerChord & { layer: WitnessedPeerLayer };

/**
 * Undirected Know chords among people in MY book who consented to visibility
 * and whose disclosed_circle (fleet visible() ∩ book) lists each other.
 * Fail closed on one-way disclosure, missing open vis, or pending Gate/intro.
 * Tags never invent a Know bond.
 */
export function witnessedPeerKnowChords(contacts: TrustEdge[]): WitnessedPeerChord[] {
  const eligible = contacts.filter((c) => isOpenVisibilityKnown(c));
  const chords: WitnessedPeerChord[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < eligible.length; i++) {
    for (let j = i + 1; j < eligible.length; j++) {
      const A = eligible[i] as ChordSource;
      const B = eligible[j] as ChordSource;
      const af = fpOf(A);
      const bf = fpOf(B);
      if (!af || !bf || af === bf) continue;
      if (!theyKnowSet(A).has(bf) || !theyKnowSet(B).has(af)) continue;
      const key = chordKey(af, bf);
      if (seen.has(key)) continue;
      seen.add(key);
      const [left, right] = af < bf ? [A, B] : [B, A];
      chords.push({ a: left.peer_fingerprint, b: right.peer_fingerprint });
    }
  }
  return chords;
}

/**
 * Consent mesh: Know filaments plus Trust filaments.
 * A Trust chord supersedes Know for the same pair (don't double-draw).
 */
export function witnessedPeerChords(contacts: TrustEdge[]): LayeredPeerChord[] {
  const trust = witnessedPeerTrustChords(contacts);
  const trustKeys = new Set(trust.map((c) => chordKey(c.a, c.b)));
  const out: LayeredPeerChord[] = trust.map((c) => ({ ...c, layer: 'trust' as const }));
  for (const c of witnessedPeerKnowChords(contacts)) {
    if (trustKeys.has(chordKey(c.a, c.b))) continue;
    out.push({ ...c, layer: 'know' });
  }
  return out;
}

export function peerTrustNeighbors(focusId: string, contacts: TrustEdge[]): Set<string> {
  const id = (focusId || '').toLowerCase();
  const out = new Set<string>();
  if (!id) return out;
  for (const { a, b } of witnessedPeerTrustChords(contacts)) {
    if (a.toLowerCase() === id) out.add(b);
    if (b.toLowerCase() === id) out.add(a);
  }
  return out;
}
