// src/lib/contacts/apply-contact-update.ts
// 0.14 — the APPLY half of the living address book (Athena's Queue-B lane).
//
// This is the write-path counterpart to Flint's 0.4 CONSUME-VERIFY floor
// (src/lib/trust/contact-update.ts). The two are deliberately SPLIT — verify lives
// in trust/, apply lives in contacts/ — so that apply CANNOT run without verify:
// the only legitimate input here is a value that `verifyIncomingContactUpdate`
// already returned. Design: AGENT_HANDOFF.md "Athena (0.14) apply"; Flint PR #10.
//
// WHAT APPLY DOES. Given a VERIFIED delta and the contact we currently store,
// produce the next stored contact and report whether this update IGNITED it
// (gray/dim -> living). Applying a verified card update is itself a meaningful,
// cryptographically-authenticated interaction with that contact, so it refreshes
// the local decay clock (`last_interaction`) — which is exactly how a DIM contact
// re-ignites to LIVING (0.14 contact-state; the 0.15 demo climax). This function
// is PURE: it never touches IndexedDB. The caller persists the returned record via
// client-store.updateContact() and, if `ignited`, plays the bloom.
//
// TWO FLOORS THIS MODULE UPHOLDS (mirroring the fail-loud spirit of 0.4-verify):
//
//   1) DEFENCE-IN-DEPTH FIREWALL. Apply independently re-asserts the allowlist
//      (CONTACT_UPDATE_ALLOWED_FIELDS). Verify is the primary firewall, but apply
//      never trusts that a value reached it only through verify — a future refactor
//      that bypasses verify must still not smuggle a field past apply.
//
//   2) NO SILENT FIELD DROP (verify/apply must not diverge). Every allowlisted
//      field must have a mapping onto the stored model, or applying it THROWS
//      ContactUpdateApplyRejected('field-not-mappable', field). There is no branch
//      that accepts a verified field and quietly discards it: a user whose card
//      says "my new phone applied" must not find it silently gone. Fields that the
//      address-book model does not yet have a home for FAIL LOUD until the
//      field-vocabulary reconciliation (see FIELD_MAP below) gives them one.
//
// SEAM NOTE (reconcile at merge, Flint PR #10 / Archie format-freeze). The stored
// model here is the live `ContactRecord` (IndexedDB, client-store.ts) — an open bag
// whose typed fields are name/email/public_key/trust_level/metadata. The three-state
// view (gray/living/dim) is DERIVED from it via contactToEdge()+getContactState(),
// not stored. The field-vocabulary reconciliation has LANDED (Archie D1 #115574 /
// Flint #115581; phones folded in per Fable 9.2 / spec §2 #115738): the allowlist is
// the canonical set {display_name,phones,emails,note}, and FIELD_MAP is the single
// reviewable place growth lands. Flint aligns his 0.4 allowlist to this set at
// merge-reconcile (divergence-guarded). See
// shared/outbox/athena/svrnty_0.14_apply_reconciliation.md.

import type { ContactState } from '../trust/contact-state';
import { getContactState } from '../trust/contact-state';

/**
 * The verified delta this module consumes. Structurally identical to
 * `VerifiedContactUpdate` in src/lib/trust/contact-update.ts (Flint 0.4) — declared
 * locally so apply is independently buildable/testable and never imports the verify
 * module (the same decoupling Flint used for his `KnownContactIdentity` seam). On
 * merge the two unify to Flint's exported type; the shape is the contract.
 */
export interface VerifiedContactUpdate {
  fingerprint: string;
  epoch: number;
  version: number;
  changed_fields: string[];
  delta: Record<string, unknown>;
}

/**
 * The minimal shape of a stored contact this module reads and writes. The live
 * `ContactRecord` (client-store.ts) satisfies it (it is an open `[key]: any` bag);
 * declared structurally so apply does not import client-store's private interface.
 * `[key: string]: unknown` carries the untyped passthrough that contactToEdge reads
 * (last_interaction, notes, tags, …) and the verify-bookkeeping fields apply writes.
 */
export interface StoredContact {
  id: string;
  fingerprint: string;
  name: string;
  email: string;
  public_key: string;
  trust_level: string;
  added_at: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export type ContactUpdateApplyRejectReason =
  | 'wrong-target' // the verified update is for a different contact than the one supplied
  | 'stale-version' // version <= the version we already applied (idempotency / replay floor)
  | 'field-not-allowed' // a changed_field is outside the allowlist (defence-in-depth firewall)
  | 'field-not-mappable'; // an allowlisted field has no home on the stored model yet — FAIL LOUD

/**
 * Thrown for every apply rejection. Its existence is the "no silent drop" floor:
 * the only alternative to a fully-applied record is this exception.
 */
export class ContactUpdateApplyRejected extends Error {
  constructor(
    public readonly reason: ContactUpdateApplyRejectReason,
    detail?: string,
  ) {
    super(detail ? `contact.update apply rejected (${reason}): ${detail}` : `contact.update apply rejected (${reason})`);
    this.name = 'ContactUpdateApplyRejected';
  }
}

/**
 * The allowlist, re-asserted here (defence-in-depth). MUST stay identical to
 * CONTACT_UPDATE_ALLOWED_FIELDS in src/lib/trust/contact-update.ts (Flint 0.4);
 * a divergence is a bug the divergence-guard test catches on merge. The absence of
 * presence/geo fields is load-bearing (I-4 / I-6) on both sides of the seam.
 *
 * Canonical set (Archie D1 #115574, KB#86066; Flint security-GO #115581; phones
 * folded in per Fable 9.2 / spec §2 #115738). Deliberately the SMALLEST vocabulary a
 * contact.update may carry — everything else fail-closes at the firewall
 * ('field-not-allowed'), the E2E floor doing its job (an older receiver rejecting an
 * unknown field). This is the shrink→grow architecture firing: the spartan floor was
 * {display_name,note,emails}; PHONES are the first earned grow — vCards are
 * phone-centric and the dedup key (9.1) normalizes on the phone, so importing a
 * contact without their number is broken, not spartan. Further growth stays FREE
 * (add to BOTH allowlists + FIELD_MAP together; breaks no signature/relay):
 *   grow-NEXT = urls (has a producer via vCard import, pending a contactToEdge home);
 *   routing → its own routing.update object type; public_key → its own key.rotate
 *   path (a rotation, not a field-set — §5/§11).
 */
export const CONTACT_UPDATE_ALLOWED_FIELDS: ReadonlySet<string> = new Set([
  'display_name', 'phones', 'emails', 'note',
]);

/**
 * How each allowlisted wire field is written onto the stored ContactRecord. This is
 * THE reconciliation surface (Flint allowlist ↔ ContactRecord ↔ TrustEdge view).
 *
 * Post-reconciliation (spartan allowlist), FIELD_MAP's keys == the allowlist: every
 * field a contact.update may carry has an UNAMBIGUOUS home that surfaces in the
 * derived view (contactToEdge). The 'field-not-mappable' throw below is therefore the
 * GROW-NEXT guard — it fires only if a future field is added to the allowlist WITHOUT
 * a FIELD_MAP entry, failing loud rather than silently dropping it (the no-silent-drop
 * floor). Extending support = add to BOTH allowlists + one entry here, together.
 *
 * OUT of the allowlist (fail-closed at the firewall as 'field-not-allowed'):
 *   given_name/family_name/org/title/birthday/postal_addresses → no producer +
 *     no ContactRecord home; rich-vCard vocabulary, deferred (grow only with a home).
 *   photo → rides vCard IMPORT as storage-passthrough (import vocab ≠ this
 *     contact.update allowlist, per spec §2); preserved-through-import, NOT a signed
 *     contact.update field — so it stays OUT here.
 *   urls → has a producer (vCard import) but contactToEdge has no home yet →
 *     grow-NEXT once that home lands (a passthrough today would store-but-never-show).
 *   routing → its own routing.update object type (a delivery redirect, not a card edit).
 *   public_key → its own key.rotate path: a rotation, not a plain field-set — a plain
 *     set would swap the active key while keeping the genesis fingerprint (bypassing the
 *     C2 fingerprint↔key binding) and skip epoch-lineage. Flint affirmed (#115581).
 */
type FieldSetter = (record: StoredContact, value: unknown) => void;

const FIELD_MAP: Readonly<Record<string, FieldSetter>> = {
  // display_name → the typed `name` (contactToEdge: peer_name ← c.name).
  display_name: (r, v) => { r.name = asString(v); },
  // note → top-level `notes` (contactToEdge reads `c.notes || c.metadata?.notes`;
  // top-level surfaces first). Flint's field is `note` (singular) — a NAME seam.
  note: (r, v) => { r.notes = asString(v); },
  // emails → primary to the typed `email` (what contactToEdge surfaces as peer_email),
  // full list preserved on `emails` passthrough. NOTE: contactToEdge does not yet
  // surface the full list — flagged in the memo as a view gap, not a data loss.
  emails: (r, v) => {
    const list = asStringArray(v);
    r.emails = list;
    if (list.length > 0) r.email = list[0];
  },
  // phones → primary to `phone`, full list preserved on `phones` (mirrors emails).
  // LOAD-BEARING (Fable 9.2): the dedup engine (9.1) normalizes on the phone and vCard
  // import produces it (contact_info.phone). Same view-gap caveat as emails —
  // contactToEdge does not surface the list yet; the data is stored, never dropped.
  phones: (r, v) => {
    const list = asStringArray(v);
    r.phones = list;
    if (list.length > 0) r.phone = list[0];
  },
};

/** The wire fields the apply FIELD_MAP can write onto a ContactRecord. Every allowlisted field MUST
 *  be a key here or apply throws 'field-not-mappable' at runtime. Exported for the CI lockstep guard
 *  so that coverage check moves from runtime to CI (closes allowlist ≡ FIELD_MAP-domain). */
export const CONTACT_UPDATE_FIELD_MAP_KEYS: ReadonlySet<string> = new Set(Object.keys(FIELD_MAP));

function asString(v: unknown): string {
  if (typeof v !== 'string') throw new ContactUpdateApplyRejected('field-not-mappable', `expected string, got ${typeof v}`);
  return v;
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string'))
    throw new ContactUpdateApplyRejected('field-not-mappable', 'expected string[]');
  return v as string[];
}

/** The `last_interaction`-equivalent the stored record carries for the decay clock. */
function currentInteraction(record: StoredContact): string | undefined {
  const li = record.last_interaction;
  return typeof li === 'string' ? li : undefined;
}

/**
 * Derive a contact's three-state from a stored record, via the same
 * ContactRecord→TrustEdge projection the live UI uses (contactToEdge). Kept minimal
 * and local: state depends only on `trusted` + the decay clock, so we project just
 * those. Mirrors contactToEdge's fallbacks (trust_level → trusted; last_interaction
 * → verified_at → added_at).
 */
function stateOf(record: StoredContact): ContactState {
  const trusted =
    typeof record.trusted === 'boolean'
      ? record.trusted
      : record.trust_level === 'verified' || record.trust_level === 'trusted';
  const last_interaction =
    currentInteraction(record) ||
    (typeof record.verified_at === 'string' ? record.verified_at : undefined) ||
    record.added_at;
  const decay_days = typeof record.decay_days === 'number' ? record.decay_days : 730;
  return getContactState({ trusted, last_interaction, decay_days } as Parameters<typeof getContactState>[0]);
}

/** The result of applying a verified update: the next record + whether it ignited. */
export interface AppliedContactUpdate {
  /** The updated stored contact — persist via client-store.updateContact(). */
  next: StoredContact;
  /** True iff this update moved the contact DIM → LIVING (play the bloom). */
  ignited: boolean;
}

/**
 * Apply a VERIFIED contact.update to the stored contact, purely.
 *
 * @param current the stored contact this update is for (its fingerprint MUST match)
 * @param update  a value returned by verifyIncomingContactUpdate (never construct by hand)
 * @param now     ISO timestamp for the refreshed decay clock (injected for determinism)
 * @returns the next record + whether it ignited (gray/dim → living)
 * @throws ContactUpdateApplyRejected on wrong target, stale version, or any
 *         allowlisted-but-unmappable field (NO silent drop).
 */
export function applyVerifiedContactUpdate(
  current: StoredContact,
  update: VerifiedContactUpdate,
  now: string,
): AppliedContactUpdate {
  // 0) Target check — this verified delta must be for the contact we hold.
  if (current.fingerprint !== update.fingerprint)
    throw new ContactUpdateApplyRejected('wrong-target', `${update.fingerprint} != ${current.fingerprint}`);

  // 1) Idempotency / replay floor at the store: never re-apply an older-or-equal
  //    version. Verify enforces this against KnownContactIdentity.version, but the
  //    stored record is the source of truth for what we have actually applied.
  const appliedVersion = typeof current.version === 'number' ? current.version : -1;
  if (update.version <= appliedVersion)
    throw new ContactUpdateApplyRejected('stale-version', `v${update.version} <= applied v${appliedVersion}`);

  const before = stateOf(current);

  // Work on a shallow copy — pure function, never mutate the caller's record.
  const next: StoredContact = { ...current };

  // 2) Apply each changed field through the firewall + field-map.
  for (const field of update.changed_fields) {
    if (!CONTACT_UPDATE_ALLOWED_FIELDS.has(field))
      throw new ContactUpdateApplyRejected('field-not-allowed', field); // defence-in-depth
    const setter = FIELD_MAP[field];
    if (!setter) throw new ContactUpdateApplyRejected('field-not-mappable', field); // no silent drop
    setter(next, update.delta[field]);
  }

  // 3) Verify-bookkeeping the stored record must carry so the monotonic/epoch floors
  //    survive a reload (ContactRecord is an open bag; these are untyped passthrough).
  next.version = update.version;
  next.epoch = update.epoch;

  // 4) A verified update is a real interaction → refresh the decay clock. This is
  //    the ignition: a trusted+DIM contact becomes LIVING. (A gray/untrusted contact
  //    stays gray — a card edit does not grant trust.)
  next.last_interaction = now;

  const after = stateOf(next);
  const ignited = before === 'dim' && after === 'living';

  return { next, ignited };
}
