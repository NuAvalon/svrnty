// src/lib/trust/affirm-wire-purge.test.ts
// Run: npx tsx --test src/lib/trust/affirm-wire-purge.test.ts
//
// #593 — exhaustive unit coverage of the PURE scrub decision that the one-time on-unlock purge applies
// over every contact record (client-store purgeAffirmWireMutualTaintOnUnlock). Proves: it scrubs the
// device-held affirm-wire taint, is idempotent, preserves last_sync, drops last_affirm_at, and no-ops on
// a clean/absent mutual. The store-iteration runner writes ONLY `{ mutual: res.mutual }` — so this pure
// decision + the runner's single-field write = the full do-no-harm contract (never touches own-trust).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scrubAffirmWireMutual } from './affirm-wire-purge';

test('scrubs a fully-tainted mutual → benign default; last_sync preserved, last_affirm_at dropped', () => {
  const r = scrubAffirmWireMutual({
    they_trust_me: true, reciprocal: true, last_affirm_at: '2026-10-10T10:00:00.000Z', last_sync: '2026-10-11T00:00:00.000Z',
  });
  assert.equal(r.changed, true);
  assert.deepEqual(r.mutual, { they_trust_me: null, reciprocal: false, last_sync: '2026-10-11T00:00:00.000Z' });
  assert.equal('last_affirm_at' in (r.mutual as object), false, 'last_affirm_at is dropped');
});

test('scrubs a break-applied mutual (they_trust_me:false is STILL a device-held bit)', () => {
  const r = scrubAffirmWireMutual({ they_trust_me: false, reciprocal: false, last_affirm_at: '2026-10-10T11:00:00.000Z', last_sync: null });
  assert.equal(r.changed, true);
  assert.deepEqual(r.mutual, { they_trust_me: null, reciprocal: false, last_sync: null });
});

test('scrubs reciprocal:true alone (they_trust_me already null)', () => {
  const r = scrubAffirmWireMutual({ they_trust_me: null, reciprocal: true, last_sync: 'ts' });
  assert.equal(r.changed, true);
  assert.deepEqual(r.mutual, { they_trust_me: null, reciprocal: false, last_sync: 'ts' });
});

test('scrubs a lingering last_affirm_at alone', () => {
  const r = scrubAffirmWireMutual({ they_trust_me: null, reciprocal: false, last_affirm_at: '2026-10-10T10:00:00.000Z', last_sync: null });
  assert.equal(r.changed, true);
  assert.deepEqual(r.mutual, { they_trust_me: null, reciprocal: false, last_sync: null });
});

test('IDEMPOTENT: a record already at the benign default is a no-op (no write)', () => {
  const r = scrubAffirmWireMutual({ they_trust_me: null, reciprocal: false, last_sync: '2026-10-11T00:00:00.000Z' });
  assert.equal(r.changed, false);
  assert.equal(r.mutual, undefined);
});

test('re-running the scrub output is a no-op (idempotence across repeated unlocks)', () => {
  const first = scrubAffirmWireMutual({ they_trust_me: true, reciprocal: true, last_affirm_at: 'x', last_sync: 'ts' });
  assert.equal(first.changed, true);
  const second = scrubAffirmWireMutual(first.mutual);
  assert.equal(second.changed, false, 'the scrubbed value carries no taint → second pass writes nothing');
});

test('no-op on absent / null / non-object mutual', () => {
  assert.equal(scrubAffirmWireMutual(undefined).changed, false);
  assert.equal(scrubAffirmWireMutual(null).changed, false);
  assert.equal(scrubAffirmWireMutual('nope').changed, false);
  assert.equal(scrubAffirmWireMutual(42).changed, false);
});

test('preserves last_sync shape (string → string, missing → null)', () => {
  assert.equal(scrubAffirmWireMutual({ they_trust_me: true, last_sync: '2026-01-01T00:00:00.000Z' }).mutual?.last_sync, '2026-01-01T00:00:00.000Z');
  assert.equal(scrubAffirmWireMutual({ they_trust_me: true }).mutual?.last_sync, null, 'absent last_sync → null');
});
