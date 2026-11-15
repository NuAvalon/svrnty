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
  // Since dev's CAS refactor the merged record is checked in finalizeContactUpdate, which casUpdateWith runs on EVERY attempt, on the
  // record that attempt read, before encrypt (buildStoredContact) and commit. updateContact AND updateContactIf both go through it.
  const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
  const start = src.indexOf('async function finalizeContactUpdate(');
  assert.ok(start > 0, 'finalizeContactUpdate exists');
  const body = src.slice(start, src.indexOf('\n}\n', start));
  const guard = body.indexOf('assertFingerprintUnchanged(existing.fingerprint, next.fingerprint)');
  assert.ok(guard > 0, 'finalizeContactUpdate must call assertFingerprintUnchanged(existing.fingerprint, next.fingerprint)');
  assert.ok(guard < body.indexOf('fingerprintMatchesKey('), 'and before the binding check (which a swapped-in valid pair would pass)');
  assert.match(src, /finalize:\s*finalizeContactUpdate,/, 'the contact CAS io finalizes with it');
  for (const fn of ['export async function updateContact(', 'export async function updateContactIf(']) {
    const f = src.slice(src.indexOf(fn), src.indexOf('\n}\n', src.indexOf(fn)));
    assert.match(f, /casUpdateWith\(contactCasIO,/, `${fn} writes through the contact CAS io`);
  }
  const cas = readFileSync(new URL('./contact-cas.ts', import.meta.url), 'utf8');
  const fin = cas.indexOf('await io.finalize(existing, built)');
  assert.ok(fin > 0 && fin < cas.indexOf('await io.encrypt(next)') && fin < cas.indexOf('await io.commit('), 'finalize runs before the record is built/written');
});
