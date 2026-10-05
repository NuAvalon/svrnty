// src/lib/trust/suppression.ts
/**
 * Piece-2 mutual-block — the durable owner-local SUPPRESSION set + the FAIL-CLOSED "is this party suppressed?"
 * predicate (task #579, spec KB#92246, Flint §F seal KB#92252, Archie re-sequence #159457).
 *
 * WHAT IT IS: F's owner-local decision about WHOM to STOP being visible to. The emit path (next layer, over
 * Athena's shared /onion transport) emits a fresh visible-affirm (visible-affirm.ts) to each contact that is
 * NOT suppressed; a suppressed target gets no affirmative → their held affirmative expires → F drops from
 * their graph, including transitively (#156420). This module is the EMIT-SIDE list + predicate. (The VIEWER
 * side — "do I hold a fresh affirmative from P?" — is the held-affirmatives store + the reveal AND-gate; a
 * DIFFERENT owner-local store. Don't conflate: suppression = who I won't show myself to; held-affirmatives =
 * who's currently showing themselves to me.)
 *
 * §C FIREWALL (NON-NEGOTIABLE): this set is owner-local and MUST NEVER ride the wire — like disclosed_circle /
 * blocked / open_visibility. The persisted record lives encrypted-at-rest in the `settings` store (client-
 * store.getSuppressionRecord/setSuppressionRecord); this module is the pure SHAPE + MECHANISM, unit-testable
 * IndexedDB-free. No import here reaches a publish/serialize path.
 *
 * ★ §F2 — ROTATION-STABLE KEYING: person entries are keyed by the suppressed party's `durable_id` (the
 * canonical fingerprint = hex(SHA256(sign‖enc‖kem‖sig)), stable across operational key-rotation — did-peer.ts),
 * NOT a contact UUID / mailbox_fp / route_id (all of which rotate). So a suppressed person stays suppressed
 * across THEIR rotation, and the whole record is F's owner-local data (survives F's rotation / mailbox-rebuild
 * / relay-transfer — it's in F's vault, not key-derived). This is the part that protects people; it builds now.
 * (The complementary emitter-rotation re-verify — the authority-commitment chain-WALK so a viewer can verify
 * F's CURRENT-key affirmative after F rotates — is deferred-pending-Flint's-§F2-ruling; its absence fails
 * UNDER-reveal, not leak.)
 *
 * ★ §F3 — FAIL-CLOSED-ON-DOUBT (Peter's "proven-tested" invariant, the HARDEST): if the record can't be read
 * (session locked / decrypt fails / malformed), `isPartySuppressed` returns TRUE (suppressed) — the emit path
 * then emits to NO ONE. "Can't confirm un-suppressed ⇒ exclude." The emit path MUST re-compute suppression
 * FRESH from (this live record + the live per-contact `blocked` flag) every pass — NEVER from a cached emit-set
 * — so no churn-recovery can replay a stale emit-set that includes a since-suppressed party.
 *
 * GROUPS are OPAQUE owner-local ids (today = contact tags; the "which group-ids does party X belong to?"
 * resolver is the CALLER's — this module commits to no product policy on what a group is, keeping it stable
 * under Peter/Hypatia's open default-discoverable/opt-out fork).
 */

/** Marker (type-level doc): this record NEVER serializes to any peer/relay path (§C firewall). */
export const SUPPRESSION_NEVER_ON_WIRE = true;

export interface SuppressionRecord {
  /** Global go-private — suppress ALL (emit to no one). The strongest, fully-unobservable scope (§F5). */
  global: boolean;
  /** Suppressed GROUPS — opaque owner-local group ids (resolver is the caller's; never on the wire). */
  groups: string[];
  /** Suppressed PERSONS — rotation-STABLE durable_ids (lowercase-hex canonical fingerprints), NOT UUIDs. */
  persons: string[];
}

export function emptySuppression(): SuppressionRecord {
  return { global: false, groups: [], persons: [] };
}

/**
 * Narrowing guard — a decrypted blob that is NOT a well-formed record is treated as ABSENT (null) by the
 * caller, which then fails CLOSED. A partial/legacy shape must never read as "nothing suppressed" (that would
 * un-suppress a survivor's blocks); an unknown shape is unreadable ⇒ suppress-all.
 */
export function isSuppressionRecord(x: unknown): x is SuppressionRecord {
  if (!x || typeof x !== 'object') return false;
  const r = x as Record<string, unknown>;
  return (
    typeof r.global === 'boolean' &&
    Array.isArray(r.groups) && r.groups.every((g) => typeof g === 'string') &&
    Array.isArray(r.persons) && r.persons.every((p) => typeof p === 'string')
  );
}

/** Normalize a party fingerprint/id to the canonical lowercase-hex form entries are stored/compared in. */
function norm(id: string | undefined | null): string {
  return (id || '').trim().toLowerCase();
}

/**
 * ★ THE §F3 FAIL-CLOSED PREDICATE. Returns true = SUPPRESS (do NOT emit a visible-affirm to this party).
 *   · rec === null (UNREADABLE: locked / decrypt-failed / malformed) ⇒ TRUE — default-EXCLUDED-on-doubt.
 *   · global ⇒ TRUE (go-private: no one).
 *   · the party's durable_id is person-listed ⇒ TRUE.
 *   · any of the party's group-ids is group-listed ⇒ TRUE.
 * The per-contact `blocked` flag (piece-1) is UNIONED at the emit callsite (it lives on the contact record,
 * not here) — so a piece-1 block auto-suppresses piece-2 affirmatives with no extra wiring. This predicate
 * owns only the durable RECORD's contribution. Never throws.
 */
export function isPartySuppressed(
  rec: SuppressionRecord | null,
  party: { durableId: string; groupIds?: readonly string[] },
): boolean {
  if (rec === null) return true;               // §F3 fail-closed-on-doubt
  if (rec.global === true) return true;
  const id = norm(party?.durableId);
  if (id.length > 0 && rec.persons.some((p) => norm(p) === id)) return true;
  const groupIds = party?.groupIds ?? [];
  for (const g of groupIds) {
    const gi = norm(g);
    if (gi.length > 0 && rec.groups.some((x) => norm(x) === gi)) return true;
  }
  return false;
}

// ── Pure mutations (return a NEW record; callers persist via client-store.setSuppressionRecord) ───────────
// De-duplicated, normalized. Idempotent — suppressing an already-suppressed target is a no-op-equivalent.

export function suppressPerson(rec: SuppressionRecord, durableId: string): SuppressionRecord {
  const id = norm(durableId);
  if (!id || rec.persons.some((p) => norm(p) === id)) return rec;
  return { ...rec, persons: [...rec.persons, id] };
}

export function unsuppressPerson(rec: SuppressionRecord, durableId: string): SuppressionRecord {
  const id = norm(durableId);
  return { ...rec, persons: rec.persons.filter((p) => norm(p) !== id) };
}

export function suppressGroup(rec: SuppressionRecord, groupId: string): SuppressionRecord {
  const g = norm(groupId);
  if (!g || rec.groups.some((x) => norm(x) === g)) return rec;
  return { ...rec, groups: [...rec.groups, g] };
}

export function unsuppressGroup(rec: SuppressionRecord, groupId: string): SuppressionRecord {
  const g = norm(groupId);
  return { ...rec, groups: rec.groups.filter((x) => norm(x) !== g) };
}

export function setGlobalSuppression(rec: SuppressionRecord, on: boolean): SuppressionRecord {
  return { ...rec, global: on === true };
}
