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

test('phones maps primary→phone and preserves the full list (dedup keys on phone)', () => {
  const { next } = applyVerifiedContactUpdate(
    contact(),
    update({ changed_fields: ['phones'], delta: { phones: ['+15551234567', '+15559876543'] } }),
    NOW,
  );
  assert.equal(next.phone, '+15551234567');
  assert.deepEqual(next.phones, ['+15551234567', '+15559876543']);
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

// ── No silent drop: every allowlisted field maps (spartan invariant) ─────────
// Post-shrink the allowlist == FIELD_MAP keys, so every allowlisted field applies
// without a 'field-not-mappable'. This is the POSITIVE form of the no-silent-drop
// floor: if a future grow adds a field to the allowlist WITHOUT a FIELD_MAP entry,
// this test fails loud — exactly the mistake the 'field-not-mappable' branch guards.
for (const field of CONTACT_UPDATE_ALLOWED_FIELDS) {
  test(`allowlisted field '${field}' has a mapping (no silent drop)`, () => {
    const delta =
      field === 'emails' || field === 'phones' || field === 'urls'
        ? { [field]: ['x'] }
        : field === 'handles'
          ? { [field]: { signal: 'x' } } // handles is a curated map, not a scalar
          : { [field]: 'x' };
    assert.doesNotThrow(() =>
      applyVerifiedContactUpdate(contact(), update({ changed_fields: [field], delta }), NOW),
    );
  });
}

// ── Fields OUTSIDE the spartan allowlist fail-close at the firewall ──────────
for (const field of ['given_name', 'family_name', 'org', 'title', 'photo', 'birthday', 'postal_addresses', 'routing']) {
  test(`non-allowlisted field '${field}' throws field-not-allowed (defence-in-depth firewall)`, () => {
    assert.throws(
      () => applyVerifiedContactUpdate(contact(), update({ changed_fields: [field], delta: { [field]: 'x' } }), NOW),
      (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-allowed',
    );
  });
}

test("public_key is fail-closed as a rotation, not a field-set (own key.rotate path)", () => {
  // A plain set would swap the active key while keeping the genesis fingerprint
  // (bypassing the C2 fingerprint↔key binding) and skip epoch-lineage. It is OUT of
  // the contact.update allowlist → 'field-not-allowed'. Rotation gets its own path.
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['public_key'], delta: { public_key: 'PK_NEW' } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-allowed',
  );
});

// ── Defence-in-depth firewall (apply re-asserts the allowlist) ──────────────

test('a field outside the allowlist throws field-not-allowed even if it reached apply', () => {
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['last_seen'], delta: { last_seen: 'now' } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-allowed',
  );
});

test('apply allowlist is the canonical set (method-grow added handles + urls)', () => {
  // The canonical contact.update vocabulary (phones
  // folded in per spec §2; handles + urls grown together in the
  // method-grow). The 0.4 verify allowlist is IDENTICAL — the cross-file
  // divergence-guard test below asserts equality now that they coexist on the branch.
  assert.deepEqual(
    [...CONTACT_UPDATE_ALLOWED_FIELDS].sort(),
    ['display_name', 'phones', 'emails', 'note', 'handles', 'urls'].sort(),
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

// ── Method-grow: handles (MERGE) + urls (REPLACE) ────────────────────
// Home is contact_info (nested) — the channel home vCard writes and contactToEdge SURFACES,
// so a revised handle actually reaches the peer's rendered card (not a store-but-never-show gap).

test('handles: a new handle writes into contact_info.handles (surfaces via contactToEdge)', () => {
  const { next } = applyVerifiedContactUpdate(
    contact(),
    update({ changed_fields: ['handles'], delta: { handles: { signal: '@alice.99' } } }),
    NOW,
  );
  assert.deepEqual((next.contact_info as Record<string, unknown>)?.handles, { signal: '@alice.99' });
});

test('handles MERGE: revising one handle preserves the others (data-loss guard)', () => {
  const c = contact({ contact_info: { handles: { signal: '@old', telegram: '@tg' } } });
  const { next } = applyVerifiedContactUpdate(
    c,
    update({ changed_fields: ['handles'], delta: { handles: { signal: '@new' } } }),
    NOW,
  );
  // signal updated, telegram UNTOUCHED — a replace-whole-map would have wiped it.
  assert.deepEqual((next.contact_info as Record<string, unknown>).handles, { signal: '@new', telegram: '@tg' });
});

test("handles removal: value '' deletes that key, preserves the rest (sentinel, NOT null)", () => {
  const c = contact({ contact_info: { handles: { signal: '@s', telegram: '@tg' } } });
  const { next } = applyVerifiedContactUpdate(
    c,
    update({ changed_fields: ['handles'], delta: { handles: { signal: '' } } }),
    NOW,
  );
  assert.deepEqual((next.contact_info as Record<string, unknown>).handles, { telegram: '@tg' });
});

test('handles value-guard: an off-curated key fails loud (field-not-mappable)', () => {
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['handles'], delta: { handles: { myspace: '@a' } } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-mappable',
  );
});

test('handles value-guard: a non-string value fails loud', () => {
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['handles'], delta: { handles: { signal: 42 as unknown as string } } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-mappable',
  );
});

test('handles value-guard: too many keys (> HANDLES_MAX_COUNT) fails loud', () => {
  const many: Record<string, string> = {};
  for (let i = 0; i < 20; i++) many[`k${i}`] = 'v'; // 20 > 16
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['handles'], delta: { handles: many } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-mappable',
  );
});

test('urls: REPLACE — the full bounded list writes into contact_info.urls', () => {
  const c = contact({ contact_info: { urls: ['https://old.example'] } });
  const { next } = applyVerifiedContactUpdate(
    c,
    update({ changed_fields: ['urls'], delta: { urls: ['https://new.example', 'https://blog.example'] } }),
    NOW,
  );
  assert.deepEqual((next.contact_info as Record<string, unknown>).urls, ['https://new.example', 'https://blog.example']);
});

test('urls value-guard: too many (> URLS_MAX_COUNT) fails loud', () => {
  const many = Array.from({ length: 12 }, (_, i) => `https://e${i}.example`);
  assert.throws(
    () => applyVerifiedContactUpdate(contact(), update({ changed_fields: ['urls'], delta: { urls: many } }), NOW),
    (e: unknown) => e instanceof ContactUpdateApplyRejected && e.reason === 'field-not-mappable',
  );
});

test('handles/urls apply is pure (caller contact_info not mutated)', () => {
  const c = contact({ contact_info: { handles: { signal: '@old' }, urls: ['https://old'] } });
  const snapshot = JSON.stringify(c);
  applyVerifiedContactUpdate(c, update({ changed_fields: ['handles'], delta: { handles: { signal: '@new' } } }), NOW);
  assert.equal(JSON.stringify(c), snapshot); // current record untouched (MERGE clones first)
});

// ── LOCKSTEP divergence-guard: apply allowlist ≡ verify allowlist ──────
// The canonical invariant is verify ≡ apply. Each file declares its OWN Set (apply never imports
// the verify FUNCTION — only the shared value constants), and THIS test is the guard that they never
// drift. The method-grow grew BOTH together; if a future grow touches only one, this fails.
test('apply allowlist ≡ verify allowlist (no drift — the lockstep guard)', async () => {
  const verify = await import('../trust/contact-update');
  assert.deepEqual(
    [...CONTACT_UPDATE_ALLOWED_FIELDS].sort(),
    [...verify.CONTACT_UPDATE_ALLOWED_FIELDS].sort(),
  );
});
