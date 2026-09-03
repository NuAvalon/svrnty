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

/** Fingerprints that form a witnessed peer-trust chord with `focusId`. */
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
