// src/lib/contacts/book-export.ts
// The .json contact-book export FIREWALL. Sibling of vcard.ts (the .vcf book export).
//
// SCAR (Apollo — KB#88313, the KB#87626 §C export-leak scar's 2nd surface): the contacts
// book-export is a data-egress surface. #82 stripped the .vcf branch (vcard.ts no longer emits
// CATEGORIES:${tags}) but MISSED the PARALLEL .json branch, which did
// JSON.stringify({ contacts: records }) — dumping the FULL device-local ContactRecord
// (tags, blocked, notes, metadata.*, last_interaction) as plaintext into a downloadable file.
// That is the exact "enumerate ALL egress" miss: fixing one surface left the parallel one leaking.
//
// FIX = an ALLOWLIST projection, not a denylist. ContactRecord is an open bag
// (`[key: string]: any`, plus `metadata: any` and a LOCAL-ONLY `last_interaction` decay clock the
// type EXPLICITLY forbids from any outbound payload — leaking it turns a private decay clock into a
// third-party activity oracle). A denylist of known-bad fields would silently leak the next private
// field anyone adds. This projects each record onto an EXPLICIT set of safe, portable identity
// fields by field-by-field construction (NO spread) — anything not named here cannot serialize.
// Fail-closed.
//
// Full-fidelity backup (tags/notes/etc.) is the ENCRYPTED vault export (VaultExportDialog), not this
// plaintext-portable book. §2 ruling: device-local {tags,blocked,group-labels,notes} must NEVER
// serialize on ANY export payload.
//
// Firewall test: book-export.test.ts asserts private sentinels never appear + safe fields survive.
// Run: npx tsx --test src/lib/contacts/book-export.test.ts

import type { ContactRecord } from '../identity/client-store';

/**
 * The ONLY fields that leave the device in a plaintext .json contact-book export. All are public
 * identity material (keys, fingerprint) or owner-benign (name / email / trust level / add-time).
 * This is the same safe set the .vcf book export (vcard.ts) exposes — the two book formats must
 * stay aligned; a field added here is a field that leaves the device.
 */
export interface SafeExportContact {
  name: string;
  email: string;
  fingerprint: string;
  public_key: string;
  pq_sig_public_key?: string;
  pq_kem_public_key?: string;
  trust_level: string;
  added_at?: string;
}

/**
 * Project a stored ContactRecord onto the safe, portable export shape.
 *
 * EXPLICIT construction IS the firewall: there is no `{ ...record }`, so no open-bag key, no
 * `metadata`, and no `last_interaction` can ride along. Add a field here ONLY if it is public
 * identity material or owner-benign — never device-local relationship metadata.
 */
export function toSafeExportContact(record: ContactRecord): SafeExportContact {
  const safe: SafeExportContact = {
    name: record.name,
    email: record.email,
    fingerprint: record.fingerprint,
    public_key: record.public_key,
    trust_level: record.trust_level,
  };
  // Public post-quantum keys — safe to carry; preserves PQ identity across a book round-trip.
  if (record.pq_sig_public_key) safe.pq_sig_public_key = record.pq_sig_public_key;
  if (record.pq_kem_public_key) safe.pq_kem_public_key = record.pq_kem_public_key;
  // Owner's own add-time (parity with the .vcf book export). This is NOT last_interaction — the
  // decay clock / activity oracle, which is deliberately excluded.
  if (record.added_at) safe.added_at = record.added_at;
  return safe;
}

/**
 * Build the downloadable .json contact-book payload. This is the ONE place the .json export is
 * serialized, so the firewall (toSafeExportContact) cannot be bypassed by a caller.
 *
 * @param exportedAt caller-supplied ISO timestamp (injected so the payload stays testable/deterministic).
 */
export function toContactBookJson(records: ContactRecord[], exportedAt: string): string {
  return JSON.stringify(
    {
      contacts: records.map(toSafeExportContact),
      exported_at: exportedAt,
    },
    null,
    2,
  );
}
