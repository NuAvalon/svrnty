// #724 (PWA half): a contact row's fingerprint can't be replaced by an update. Behavioural on the pure rule, plus a static
// guard that client-store.updateContact applies it BEFORE anything is written (client-store needs IndexedDB, so its other
// tests are static too, e.g. verify-before-trust.test.ts).
// Run: npx tsx --test src/lib/identity/contact-identity.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assertFingerprintUnchanged } from './contact-identity';

const X = 'ab'.repeat(32);
const Y = 'cd'.repeat(32);

test('P1 replacing a set fingerprint is refused (the trusted row, and what it may see, stays with X)', () => {
  assert.throws(() => assertFingerprintUnchanged(X, Y), /immutable/);
  assert.throws(() => assertFingerprintUnchanged(X, ''), /immutable/, 'clearing it is a replace too (unlink, then link elsewhere)');
  assert.throws(() => assertFingerprintUnchanged(X, undefined), /immutable/);
});

test('P2 unchanged (any case / whitespace) passes; a key-less row may be linked to its first identity', () => {
  assert.doesNotThrow(() => assertFingerprintUnchanged(X, X));
  assert.doesNotThrow(() => assertFingerprintUnchanged(X, ` ${X.toUpperCase()} `));
  assert.doesNotThrow(() => assertFingerprintUnchanged('', Y), 'Link to SVRNTY on an unlinked contact');
  assert.doesNotThrow(() => assertFingerprintUnchanged(undefined, Y));
});

test('P3 client-store.updateContact applies the rule to the merged record before it builds or writes anything', () => {
  const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
  const start = src.indexOf('export async function updateContact(');
  const body = src.slice(start, src.indexOf('\nexport ', start + 1));
  const guard = body.indexOf('assertFingerprintUnchanged(existing.fingerprint, next.fingerprint)');
  assert.ok(guard > 0, 'updateContact must call assertFingerprintUnchanged(existing.fingerprint, next.fingerprint)');
  assert.ok(guard < body.indexOf('buildStoredContact('), 'the rule must run before the record is built/written');
  assert.ok(guard < body.indexOf('fingerprintMatchesKey('), 'and before the binding check (which a swapped-in valid pair would pass)');
});
