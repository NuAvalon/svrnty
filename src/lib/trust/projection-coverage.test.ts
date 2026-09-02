// src/lib/trust/projection-coverage.test.ts
// Run: npx tsx --test src/lib/trust/projection-coverage.test.ts
//
// CLASS-KILLER (Peter's rider, #118456). A "view gap" is a field the store PERSISTS
// but the record→edge projection silently DROPS — invisible in the UI, no error, no
// crash. This class bit us twice: pq_* keys (the HNDL hole) and contact_info phones
// (Chaos#40). Both were "a field vanishes at the record→edge boundary."
//
// This test makes that gap IMPOSSIBLE to introduce silently: it asserts every field a
// fully-populated ContactRecord carries either (a) surfaces in the projected TrustEdge,
// or (b) is named on the explicit DEFERRED list with a reason. Add a new persisted
// field and forget to project it → this test goes RED and names the field.
//
// Check is by VALUE-PRESENCE, not field name, because contactRecordToEdge RENAMES
// (fingerprint→peer_fingerprint, pq_*→peer_pq_*): a renamed field keeps its value, so
// value-presence still proves it survived. Only TRANSFORMED/internal fields (whose
// verbatim value legitimately disappears) go on DEFERRED.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contactRecordToEdge } from './contact-edge';

// A ContactRecord with EVERY persisted field set to a unique, findable sentinel.
// contact_info is an OPEN-BAG field (not in the declared interface, but really
// persisted via `{ ...contact }` in addContact) — and it is exactly the field that
// was being dropped, so it MUST be covered.
const FULL_RECORD = {
  id: 'REC_id',
  fingerprint: 'REC_fingerprint',
  name: 'REC_name',
  email: 'REC_email',
  public_key: 'REC_public_key',
  pq_sig_public_key: 'REC_pq_sig',
  pq_kem_public_key: 'REC_pq_kem',
  trust_level: 'trusted', // NB: a real enum value, not a sentinel — see DEFERRED
  added_at: 'REC_added_at',
  metadata: { tags: ['REC_tag'], notes: 'REC_notes' },
  epoch: 424242,
  version: 77,
  last_interaction: 'REC_last_interaction',
  owner_fingerprint: 'REC_owner_fingerprint',
  contact_info: {
    phones: ['REC_phone'],
    emails: ['REC_ci_email'],
    urls: ['REC_url'],
    handles: { signal: 'REC_handle' },
  },
  they_trust: ['REC_they_trust'],
};

// Fields intentionally NOT carried verbatim onto the edge — each with a reason.
// A field here is a DELIBERATE deferral; anything NOT here must surface.
const DEFERRED: Record<string, string> = {
  trust_level: 'transformed → edge.trusted (boolean); the string is consumed, not carried',
  epoch: 'local verify bookkeeping (identity_epoch floor) — not a peer/display field',
  version: 'local verify bookkeeping (revision floor) — not a peer/display field',
  owner_fingerprint: "the owner's OWN fingerprint (record ownership index), not peer data",
};

// Deep-collect every primitive value in a value (for value-presence search).
function primitives(v: unknown, out: Set<string> = new Set()): Set<string> {
  if (v === null || v === undefined) return out;
  if (typeof v === 'object') {
    for (const val of Object.values(v as Record<string, unknown>)) primitives(val, out);
  } else {
    out.add(String(v));
  }
  return out;
}

test('projection-coverage: every persisted ContactRecord field surfaces on the edge (or is explicitly DEFERRED)', () => {
  const edge = contactRecordToEdge(FULL_RECORD);
  const edgeValues = primitives(edge);

  const gaps: string[] = [];
  for (const field of Object.keys(FULL_RECORD)) {
    if (field in DEFERRED) continue;
    const missing = [...primitives((FULL_RECORD as Record<string, unknown>)[field])].filter(
      (val) => !edgeValues.has(val),
    );
    if (missing.length) {
      gaps.push(`${field} → dropped value(s): [${missing.join(', ')}]`);
    }
  }

  assert.deepEqual(
    gaps,
    [],
    'VIEW GAP: field(s) persisted on ContactRecord but silently dropped by contactRecordToEdge.\n' +
      'Fix: surface the field on the TrustEdge, OR add it to DEFERRED with a reason.\n  ' +
      gaps.join('\n  '),
  );
});

test('DEFERRED stays honest: each deferred field really is absent verbatim (else it is not a deferral)', () => {
  const edge = contactRecordToEdge(FULL_RECORD);
  const edgeValues = primitives(edge);
  const lies: string[] = [];
  for (const field of Object.keys(DEFERRED)) {
    const values = [...primitives((FULL_RECORD as Record<string, unknown>)[field])];
    // trust_level='trusted' → edge.trusted is boolean true; the STRING 'trusted' must not appear.
    if (values.some((v) => edgeValues.has(v))) {
      lies.push(`${field}: a sentinel surfaces on the edge — it is projected, not deferred`);
    }
  }
  assert.deepEqual(lies, [], `DEFERRED list is stale:\n  ${lies.join('\n  ')}`);
});
