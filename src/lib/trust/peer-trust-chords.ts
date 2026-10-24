/**
 * Witnessed peer↔peer trust chords — the open-visibility spec.
 *
 * If I trust Sally and Joe, they trust me, and we all have open visibility
 * for trusted contacts, I see that they trust each other (and they see that
 * I trust them). That is consented disclosure, not Facebook-style inference.
 *
 * Glass NEVER computes PSI. It only draws a chord when both edges already
 * carry fleet-filled (or demo stand-in) fields AND the local open-visibility
 * predicate holds. This module does not start know-layer sync (that is
 * ContactManagement -> startKnowLayerSync, gated on `isPSIDiscoveryLive()`).
 * Co-membership of an owner tag is not a bond.
 * `metadata.mutual_contacts` (card-exchange leftover) is NOT disclosed_circle.
 *
 * CONSENT (#255, two-tier): owner visibility toward a peer is a per-person
 * override on top of a per-tier global default (default OFF, Archie spec v2
 * #170171). Evaluated LIVE at query time — there is no materialized edge, so
 * toggling either level off drops the chord on the next call.
 *   • TRUSTED tier per-person = open_visibility (swept on untrust by the #111
 *     honor-severance migration — that's correct: untrust exits the trusted tier).
 *   • KNOWN tier   per-person = share_settings.known_visibility (a sibling the
 *     #111 sweep PRESERVES — known ≠ trust, so untrust must NOT drop a known chord),
 *     falling back to legacy open_visibility for backward-compat.
 * A per-person boolean (true OR false) WINS over the global default; unset
 * inherits the tier's global default.
 *
 * SEVERANCE (Flint gate): a blocked contact NEVER rides the chord mesh — the
 * shared `chordEligible` base applies the canonical `!blocked` guard
 * (admitContact) to BOTH tiers and the global-default path, at the render
 * chokepoint, regardless of tier/field/global-default. Block is suppression +
 * flag (not a remove), so without this guard a blocked peer whose open_visibility
 * was never cleared would still be drawn. The guard also closes the pre-existing
 * latent trusted-tier exposure (blocked + trusted + open_vis → chord) independent
 * of #255.
 *
 * SCOPE: the global default feeds ONLY this chord predicate. It is structurally
 * unreachable from allowed-sync.ts (discovery / allowed_senders) — this module
 * does not import it — so flipping a global "see each other" toggle NEVER makes
 * a contact discoverable to strangers.
 */

import type { TrustEdge } from '@/lib/trust/types';
import { admitContact } from '@/lib/trust/admit-contact';

export type WitnessedPeerChord = {
  a: string;
  b: string;
};

export type WitnessedPeerLayer = 'know' | 'trust';

export type LayeredPeerChord = WitnessedPeerChord & { layer: WitnessedPeerLayer };

/**
 * Owner's per-tier global default: do my mutually-{known,trusted} contacts see
 * each other by default? Both default OFF (#255 — opt-in, revocable). A per-person
 * setting overrides the matching tier.
 */
export interface GlobalOpenVisibility {
  known: boolean;
  trusted: boolean;
}

/** All-off default — the safe baseline when the owner has set no global toggle. */
export const GLOBAL_OPEN_VISIBILITY_OFF: GlobalOpenVisibility = { known: false, trusted: false };

type ChordSource = TrustEdge & {
  open_visibility?: boolean;
  peer_mutual?: Array<{ peer_fingerprint: string }>;
  metadata?: {
    they_trust?: string[];
    blocked?: boolean;
    share_settings?: { open_visibility?: boolean; known_visibility?: boolean };
  };
};

function fpOf(c: TrustEdge): string {
  return (c.peer_fingerprint || '').toLowerCase();
}

/** A set value only if it is an explicit boolean; undefined means "inherit the global default". */
function triState(v: unknown): boolean | undefined {
  return typeof v === 'boolean' ? v : undefined;
}

function theyTrustSet(c: ChordSource): Set<string> {
  const ids = [
    ...(c.they_trust || []),
    ...(c.metadata?.they_trust || []),
    ...((c.peer_mutual || []).map((p) => p.peer_fingerprint)),
  ];
  return new Set(ids.map((id) => (id || '').toLowerCase()).filter(Boolean));
}

/**
 * Per-person TRUSTED-tier visibility override (tri-state). open_visibility is the
 * trusted-tier owner intent; share_settings.open_visibility is its metadata mirror.
 */
function perPersonTrustedVis(c: ChordSource): boolean | undefined {
  return triState(c.open_visibility) ?? triState(c.metadata?.share_settings?.open_visibility);
}

/**
 * Per-person KNOWN-tier visibility override (tri-state). known_visibility is the
 * un-swept sibling (#255); falls back to legacy open_visibility for backward-compat.
 */
function perPersonKnownVis(c: ChordSource): boolean | undefined {
  return (
    triState(c.metadata?.share_settings?.known_visibility) ??
    triState(c.open_visibility) ??
    triState(c.metadata?.share_settings?.open_visibility)
  );
}

/**
 * Owner opted in toward this peer for the given tier: per-person override (if set),
 * else the tier's global default. The single consent chokepoint — both tiers route here.
 */
export function ownerVisibilityToward(
  c: ChordSource,
  tier: WitnessedPeerLayer,
  globals: GlobalOpenVisibility = GLOBAL_OPEN_VISIBILITY_OFF,
): boolean {
  const perPerson = tier === 'trust' ? perPersonTrustedVis(c) : perPersonKnownVis(c);
  if (perPerson !== undefined) return perPerson;
  return tier === 'trust' ? globals.trusted : globals.known;
}

/**
 * Shared chord-eligibility floor applied to BOTH tiers (Flint gate): the peer is
 * not blocked (canonical !blocked dual, admitContact) and has a fingerprint.
 * Severance bites here regardless of tier / field / global-default.
 */
function chordEligible(c: TrustEdge): boolean {
  return admitContact(c) && !!fpOf(c);
}

/**
 * Eligible for open-visibility peer chords with the owner:
 * not blocked, trusted by me, they trust me, and I opened visibility toward them
 * (per-person override, else the trusted-tier global default).
 */
export function isOpenVisibilityMutual(c: TrustEdge, globals?: GlobalOpenVisibility): boolean {
  if (!chordEligible(c)) return false;
  if (!c.trusted) return false;
  const theyTrustMe = c.mutual?.reciprocal === true || c.mutual?.they_trust_me === true;
  if (!theyTrustMe) return false;
  return ownerVisibilityToward(c as ChordSource, 'trust', globals);
}

/**
 * Undirected chords among people in MY book who mutually trust me, have
 * open visibility, and whose `they_trust` lists include each other.
 * Fail closed on one-way they_trust, missing open vis, or non-reciprocal.
 */
export function witnessedPeerTrustChords(
  contacts: TrustEdge[],
  globals?: GlobalOpenVisibility,
): WitnessedPeerChord[] {
  const eligible = contacts.filter((c) => isOpenVisibilityMutual(c, globals) && fpOf(c));
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
    metadata?: { disclosed_circle?: string[] };
  };
  const ids = [
    ...(extra.disclosed_circle || []),
    ...(extra.metadata?.disclosed_circle || []),
  ];
  return new Set(ids.map((id) => (id || '').toLowerCase()).filter(Boolean));
}

function isPendingStar(c: TrustEdge): boolean {
  const e = c as TrustEdge & { connection_status?: string; pending_intro?: unknown };
  return e.connection_status === 'pending' || !!e.pending_intro;
}

/**
 * Eligible for open-visibility Know chords with the owner:
 * not blocked, in the book (Known), not pending, and I opened visibility toward
 * them (per-person override, else the known-tier global default).
 * Trust is NOT required — Know ≠ Trust.
 */
export function isOpenVisibilityKnown(c: TrustEdge, globals?: GlobalOpenVisibility): boolean {
  if (!chordEligible(c)) return false;
  if (isPendingStar(c)) return false;
  return ownerVisibilityToward(c as ChordSource, 'know', globals);
}

function chordKey(a: string, b: string): string {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  return x < y ? `${x}|${y}` : `${y}|${x}`;
}

/**
 * Undirected Know chords among people in MY book who consented to visibility
 * and whose disclosed_circle (fleet visible() ∩ book) lists each other.
 * Fail closed on one-way disclosure, missing open vis, or pending Gate/intro.
 * Tags never invent a Know bond.
 */
export function witnessedPeerKnowChords(
  contacts: TrustEdge[],
  globals?: GlobalOpenVisibility,
): WitnessedPeerChord[] {
  const eligible = contacts.filter((c) => isOpenVisibilityKnown(c, globals));
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
export function witnessedPeerChords(
  contacts: TrustEdge[],
  globals?: GlobalOpenVisibility,
): LayeredPeerChord[] {
  const trust = witnessedPeerTrustChords(contacts, globals);
  const trustKeys = new Set(trust.map((c) => chordKey(c.a, c.b)));
  const out: LayeredPeerChord[] = trust.map((c) => ({ ...c, layer: 'trust' as const }));
  for (const c of witnessedPeerKnowChords(contacts, globals)) {
    if (trustKeys.has(chordKey(c.a, c.b))) continue;
    out.push({ ...c, layer: 'know' });
  }
  return out;
}

export function peerTrustNeighbors(
  focusId: string,
  contacts: TrustEdge[],
  globals?: GlobalOpenVisibility,
): Set<string> {
  const id = (focusId || '').toLowerCase();
  const out = new Set<string>();
  if (!id) return out;
  for (const { a, b } of witnessedPeerTrustChords(contacts, globals)) {
    if (a.toLowerCase() === id) out.add(b);
    if (b.toLowerCase() === id) out.add(a);
  }
  return out;
}
