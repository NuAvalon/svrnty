// src/lib/contacts/book-export.test.ts
// FIREWALL TEST for the .json contact-book export (Apollo — KB#88313, the export-leak scar's 2nd
// surface). Inverts the projection-coverage pattern: instead of asserting every field SURVIVES,
// it asserts every PRIVATE / device-local field is ABSENT from the export, and the safe identity
// fields DO survive. Widen the allowlist in book-export.ts by mistake → this goes RED and names it.
// Run: npx tsx --test src/lib/contacts/book-export.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ContactRecord } from '../identity/client-store';
import { toContactBookJson, toSafeExportContact } from './book-export';

// Fixed exported_at — no substring overlap with any sentinel below.
const EXPORTED_AT = '2026-01-02T03:04:05.000Z';

// The exact set of keys allowed to leave the device (== SafeExportContact).
const ALLOWED_KEYS = new Set([
  'name',
  'email',
  'fingerprint',
  'public_key',
  'pq_sig_public_key',
  'pq_kem_public_key',
  'trust_level',
  'added_at',
]);

// A record with EVERY safe field (SAFE_*) plus EVERY private / device-local field (PRIV_*) set to a
// unique, findable sentinel — including the open-bag surfaces a denylist would miss: top-level
// tags/blocked/notes, the metadata bag, the last_interaction activity oracle, and a bare
// future/dynamic key. The index signature on ContactRecord permits these extras.
const FULL_RECORD: ContactRecord = {
  // — safe, must survive —
  id: 'PRIV_id', // NB: local record id — deliberately NOT exported
  name: 'SAFE_name',
  email: 'SAFE_email',
  fingerprint: 'SAFE_fingerprint',
  public_key: 'SAFE_public_key',
  pq_sig_public_key: 'SAFE_pq_sig',
  pq_kem_public_key: 'SAFE_pq_kem',
  trust_level: 'trusted',
  added_at: 'SAFE_added_at',
  // — private / device-local, must NEVER serialize —
  last_interaction: 'PRIV_last_interaction',
  epoch: 424242,
  version: 7777,
  owner_fingerprint: 'PRIV_owner_fingerprint',
  tags: ['PRIV_toplevel_tag'],
  blocked: true,
  notes: 'PRIV_toplevel_notes',
  metadata: {
    tags: ['PRIV_meta_tag'],
    notes: 'PRIV_meta_notes',
    blocked: true,
    owner_verify: 'PRIV_owner_verify',
    distress_inbound: true,
    connection_status: 'PRIV_connection_status',
    group_labels: ['PRIV_group_label'],
  },
  a_future_field: 'PRIV_future_dynamic',
};

const SAFE_SENTINELS = [
  'SAFE_name',
  'SAFE_email',
  'SAFE_fingerprint',
  'SAFE_public_key',
  'SAFE_pq_sig',
  'SAFE_pq_kem',
  'SAFE_added_at',
];

// Every PRIV_* string sentinel + the numeric private values, as they would appear in JSON text.
const PRIVATE_SENTINELS = [
  'PRIV_id',
  'PRIV_last_interaction',
  'PRIV_owner_fingerprint',
  'PRIV_toplevel_tag',
  'PRIV_toplevel_notes',
  'PRIV_meta_tag',
  'PRIV_meta_notes',
  'PRIV_owner_verify',
  'PRIV_connection_status',
  'PRIV_group_label',
  'PRIV_future_dynamic',
  '424242', // epoch
  '7777', // version
];

test('firewall: exported contact has ONLY allowlisted keys (structural — catches booleans/objects too)', () => {
  const parsed = JSON.parse(toContactBookJson([FULL_RECORD], EXPORTED_AT));
  const extraneous = Object.keys(parsed.contacts[0]).filter((k) => !ALLOWED_KEYS.has(k));
  assert.deepEqual(
    extraneous,
    [],
    'EXPORT LEAK: non-allowlisted key(s) reached the .json contact-book export. toSafeExportContact() ' +
      'must expose ONLY safe identity fields (SafeExportContact). Leaked: ' +
      extraneous.join(', '),
  );
});

test('firewall: NO private/device-local value serializes (defends nested metadata + the activity oracle)', () => {
  const json = toContactBookJson([FULL_RECORD], EXPORTED_AT);
  const leaked = PRIVATE_SENTINELS.filter((s) => json.includes(s));
  assert.deepEqual(
    leaked,
    [],
    'EXPORT LEAK: private sentinel value(s) appeared in the .json contact-book export text.\n  leaked: ' +
      leaked.join(', '),
  );
});

test('no over-strip: every safe identity field survives the projection', () => {
  const json = toContactBookJson([FULL_RECORD], EXPORTED_AT);
  const missing = SAFE_SENTINELS.filter((s) => !json.includes(s));
  assert.deepEqual(missing, [], 'OVER-STRIP: safe identity field(s) dropped from export: ' + missing.join(', '));

  const safe = toSafeExportContact(FULL_RECORD);
  assert.equal(safe.trust_level, 'trusted', 'trust_level must survive (enum value, not a sentinel)');
  assert.equal(safe.name, 'SAFE_name');
  assert.equal(safe.fingerprint, 'SAFE_fingerprint');
});

test('optional public keys omitted cleanly when absent (no undefined noise / no crash)', () => {
  const minimal: ContactRecord = {
    id: 'PRIV_id2',
    name: 'SAFE_min_name',
    email: '',
    fingerprint: 'SAFE_min_fp',
    public_key: 'SAFE_min_pk',
    trust_level: 'unverified',
    added_at: 'SAFE_min_added',
  };
  const safe = toSafeExportContact(minimal);
  assert.ok(!('pq_sig_public_key' in safe), 'absent pq_sig must be omitted, not undefined');
  assert.ok(!('pq_kem_public_key' in safe), 'absent pq_kem must be omitted, not undefined');
});
