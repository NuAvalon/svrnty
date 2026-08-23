// src/lib/trust/contact-edge.ts
// The ONE ContactRecord → TrustEdge projection. Single source of truth so no field silently
// vanishes at the record→edge boundary — that bug class is Peter's "PQ-keys-dropped-on-every-edge":
// pq_* were stored on the ContactRecord (client-store.ts open bag), but the live UI built its
// TrustEdges through hand-rolled inline maps (app/page.tsx main map + JoinerCeremony lattice) that
// enumerated a fixed field list and never carried pq — so pq was dropped on every projected edge.
//
// Everything that turns a stored contact into a TrustEdge projects through THIS function:
//   - the live UI (app/page.tsx TrustMap, JoinerCeremony lattice),
//   - the import/dedup path (Apollo — dedupeContacts `existing` is projected upstream here).
// ContactRecord stores `pq_*_public_key`; TrustEdge exposes `peer_pq_*_public_key` — the fallback
// carries either shape so a record OR an already-edge-shaped object both project correctly.

import type { TrustEdge } from './types';

/**
 * Project a stored contact record onto a TrustEdge for display / trust-graph / encryption use.
 * Accepts the open-bag ContactRecord (or an already-edge-shaped object) via `peer_X || X` fallbacks.
 *
 * Carries the post-quantum keys (`peer_pq_kem_public_key` / `peer_pq_sig_public_key`) through — a
 * TrustEdge with undefined pq silently downgrades the encrypt-toward-peer path to classical (the
 * HNDL hole re-opened at the projection layer), so the projection MUST surface them.
 */
export function contactRecordToEdge(c: any): TrustEdge {
  return {
    id: c.id,
    peer_fingerprint: c.peer_fingerprint || c.fingerprint || c.id,
    peer_name: c.peer_name || c.name,
    peer_email: c.peer_email || c.email || '',
    peer_public_key: c.peer_public_key || c.public_key || '',
    trusted: c.trusted ?? (c.trust_level === 'verified' || c.trust_level === 'trusted'),
    trusted_since: c.trusted_since || c.verified_at || null,
    last_interaction: c.last_interaction || c.verified_at || c.added_at || new Date().toISOString(),
    decay_days: c.decay_days || 730,
    trust_history: c.trust_history || [],
    verification: c.verification || { method: 'none', verified_at: null },
    mutual: c.mutual || { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: c.tags || c.metadata?.tags || [],
    notes: c.notes || c.metadata?.notes || '',
    connection_channels: c.connection_channels || [],
    // Contact channels (phones/emails/urls/handles) — carry them so vCard-imported phones survive the
    // record→edge projection. Chaos#40: phones parse (vcard.ts) + persist (ContactRecord) but were
    // dropped HERE, the same "field vanishes at the record→edge boundary" class this file kills for pq.
    contact_info: c.contact_info,
    added_at: c.added_at || new Date().toISOString(),
    // Post-quantum keys — the fix for "PQ-keys-dropped-on-every-edge". ContactRecord stores
    // `pq_*_public_key`; a peer-shaped source may already carry `peer_pq_*`. Carry either.
    peer_pq_sig_public_key: c.peer_pq_sig_public_key || c.pq_sig_public_key,
    peer_pq_kem_public_key: c.peer_pq_kem_public_key || c.pq_kem_public_key,
  } as TrustEdge;
}
