// src/lib/contacts/apply-contact-update.test.ts
// 0.14 apply — the write-path floor. Run: npx tsx --test src/lib/contacts/apply-contact-update.test.ts
// (or tsc→CJS then `node`, per the repo's extensionless-source convention).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyVerifiedContactUpdate,
  ContactUpdateApplyRejected,
  CONTACT_UPDATE_ALLOWED_FIELDS,
  type StoredContact,
  type VerifiedContactUpdate,
} from './apply-contact-update';

const NOW = new Date().toISOString();
const LONG_AGO = '2019-01-01T00:00:00.000Z'; // > 730d before any plausible test clock → decayed

function contact(over: Partial<StoredContact> = {}): StoredContact {
  return {
    id: 'c1',
    fingerprint: 'FP_ALICE',
    name: 'Alice',
    email: 'alice@old.example',
    public_key: 'PK_ALICE',
    trust_level: 'trusted',
    added_at: '2024-01-01T00:00:00.000Z',
    version: 1,
    ...over,
  };
}

function update(over: Partial<VerifiedContactUpdate> = {}): VerifiedContactUpdate {
  return {
    fingerprint: 'FP_ALICE',
    epoch: 0,
    version: 2,
    changed_fields: ['display_name'],
    delta: { display_name: 'Alice A.' },
    ...over,
  };
}

// ── Field mapping (the reconciliation surface) ──────────────────────────────

test('display_name maps to the typed `name`', () => {
  const { next } = applyVerifiedContactUpdate(contact(), update(), NOW);
  assert.equal(next.name, 'Alice A.');
});

test('note maps to top-level `notes` (what contactToEdge surfaces first)', () => {
  const { next } = applyVerifiedContactUpdate(
    contact(),
    update({ changed_fields: ['note'], delta: { note: 'met at the equinox' } }),
    NOW,
  );
  assert.equal(next.notes, 'met at the equinox');
});

test('emails maps primary→email and preserves the full list', () => {
  const { next } = applyVerifiedContactUpdate(
    contact(),
    update({ changed_fields: ['emails'], delta: { emails: ['a@new.example', 'a@alt.example'] } }),
    NOW,
  );
  assert.equal(next.email, 'a@new.example');
  assert.deepEqual(next.emails, ['a@new.example', 'a@alt.example']);
});

test('multiple mapped fields apply together', () => {
  const { next } = applyVerifiedContactUpdate(
    contact(),
    update({
      changed_fields: ['display_name', 'note'],
      delta: { display_name: 'Alice A.', note: 'n' },
    }),
    NOW,
  );
  assert.equal(next.name, 'Alice A.');
  assert.equal(next.notes, 'n');
});

// ── No silent drop: allowlisted-but-unmapped fields FAIL LOUD ────────────────

for (const field of ['phones', 'urls', 'given_name', 'family_name', 'org', 'title', 'photo', 'birthday', 'postal_addresses', 'routing']) {
  test(`unmapped allowlisted field '${field}' throws field-not-mappable (no silent drop)`, () => {
    assert.throws(
      () => applyVerifiedContactUpdate(contact(), update({ changed_fields: [field], delta: { [field]: 'x' } }), NOW),
      (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-mappable',
    );
  });
}

test("public_key is fail-closed (rotation collides with C2 binding + epoch lineage)", () => {
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['public_key'], delta: { public_key: 'PK_NEW' } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-mappable',
  );
});

// ── Defence-in-depth firewall (apply re-asserts the allowlist) ──────────────

test('a field outside the allowlist throws field-not-allowed even if it reached apply', () => {
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['last_seen'], delta: { last_seen: 'now' } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-allowed',
  );
});

test('apply allowlist stays identical to the 0.4-verify allowlist (merge guard)', () => {
  // If this fails, verify and apply have diverged — reconcile before merge.
  assert.deepEqual(
    [...CONTACT_UPDATE_ALLOWED_FIELDS].sort(),
    ['birthday', 'display_name', 'emails', 'family_name', 'given_name', 'note', 'org', 'photo',
      'phones', 'postal_addresses', 'public_key', 'routing', 'title', 'urls'].sort(),
  );
});

// ── Target + replay floors ──────────────────────────────────────────────────

test('wrong target (fingerprint mismatch) throws', () => {
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ fingerprint: 'FP_MALLORY' }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'wrong-target',
  );
});

test('stale version (<= applied) throws — idempotency/replay floor', () => {
  assert.throws(
    () => applyVerifiedContactUpdate(contact({ version: 5 }), update({ version: 5 }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'stale-version',
  );
});

test('a fresh contact with no stored version accepts version 0+', () => {
  const c = contact();
  delete (c as Record<string, unknown>).version;
  const { next } = applyVerifiedContactUpdate(c, update({ version: 0 }), NOW);
  assert.equal(next.version, 0);
});

// ── Bookkeeping the stored record must carry ────────────────────────────────

test('applied version, epoch, and last_interaction are recorded', () => {
  const { next } = applyVerifiedContactUpdate(contact(), update({ version: 7, epoch: 3 }), NOW);
  assert.equal(next.version, 7);
  assert.equal(next.epoch, 3);
  assert.equal(next.last_interaction, NOW);
});

// ── Ignition (the living book) ──────────────────────────────────────────────

test('a trusted DIM contact ignites to LIVING (ignited=true)', () => {
  const dim = contact({ trust_level: 'trusted', last_interaction: LONG_AGO, decay_days: 730 });
  const { ignited, next } = applyVerifiedContactUpdate(dim, update(), NOW);
  assert.equal(ignited, true);
  assert.equal(next.last_interaction, NOW);
});

test('an untrusted GRAY contact does not ignite (a card edit grants no trust)', () => {
  const gray = contact({ trust_level: 'unverified', last_interaction: LONG_AGO });
  const { ignited } = applyVerifiedContactUpdate(gray, update(), NOW);
  assert.equal(ignited, false);
});

test('an already-LIVING contact does not re-ignite (no bloom on a fresh contact)', () => {
  const living = contact({ trust_level: 'trusted', last_interaction: NOW, decay_days: 730 });
  const { ignited } = applyVerifiedContactUpdate(living, update(), NOW);
  assert.equal(ignited, false);
});

// ── Purity ──────────────────────────────────────────────────────────────────

test('the caller record is never mutated (pure function)', () => {
  const c = contact({ name: 'Alice' });
  const snapshot = JSON.stringify(c);
  applyVerifiedContactUpdate(c, update(), NOW);
  assert.equal(JSON.stringify(c), snapshot);
});
