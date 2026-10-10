// Envelope field / signing-input tests. Run: npx tsx --test src/lib/format/envelope.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DOMAIN_TRUST_SIGNAL, DOMAIN_CONTACT_UPDATE, DOMAIN_SLUG_CLAIM,
  contactUpdateSigningInput, slugClaimSigningInput,
} from './envelope';

test('domain tags are the agreed protocol strings', () => {
  assert.equal(DOMAIN_TRUST_SIGNAL, 'svrnty:trust-signal:v1');
  assert.equal(DOMAIN_CONTACT_UPDATE, 'svrnty:contact-update:v1');
  assert.equal(DOMAIN_SLUG_CLAIM, 'svrnty:slug-claim:v1');
});

test('contactUpdateSigningInput: canonical, key-order-independent, excludes signature', () => {
  const a = { fingerprint: 'FP', epoch: 1, version: 3, updated_at: '2026-01-01T00:00:00Z', changed_fields: ['bio'], delta: { bio: 'hi' } };
  const b = { delta: { bio: 'hi' }, changed_fields: ['bio'], updated_at: '2026-01-01T00:00:00Z', version: 3, epoch: 1, fingerprint: 'FP' };
  assert.equal(contactUpdateSigningInput(a), contactUpdateSigningInput(b)); // order-independent
  assert.equal(contactUpdateSigningInput({ ...a, signature: 'zzz' } as never), contactUpdateSigningInput(a)); // sig excluded
});

test('slugClaimSigningInput: stable canonical bytes for the F6 fix', () => {
  const c = { slug: 'alice', fingerprint: 'FP', public_key: 'PK', timestamp: '2026-01-01T00:00:00Z' };
  assert.equal(slugClaimSigningInput(c), '{"fingerprint":"FP","public_key":"PK","slug":"alice","timestamp":"2026-01-01T00:00:00Z"}');
});
