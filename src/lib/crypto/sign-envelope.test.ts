// Sign-envelope framing tests — the domain-separation / suite-binding math, no keys needed.
// Run: npx tsx --test src/lib/crypto/sign-envelope.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lengthPrefix, buildSignedBytes, SUITE_CLASSICAL, SUITE_HYBRID } from './sign-envelope';
import { DOMAIN_TRUST_SIGNAL, DOMAIN_SLUG_CLAIM } from '../format/envelope';

test('lengthPrefix: decimal length, colon, value', () => {
  assert.equal(lengthPrefix(''), '0:');
  assert.equal(lengthPrefix('abc'), '3:abc');
  assert.equal(lengthPrefix('svrnty:slug-claim:v1'), '20:svrnty:slug-claim:v1');
});

test('lengthPrefix: length counts UTF-8 BYTES, not code units', () => {
  assert.equal(lengthPrefix('é'), '2:é'); // U+00E9 = 2 UTF-8 bytes
  assert.equal(lengthPrefix('世'), '3:世'); // U+4E16 = 3 UTF-8 bytes
  assert.equal(lengthPrefix('🔥'), '4:🔥'); // astral plane = 4 UTF-8 bytes
});

test('buildSignedBytes: LP(domain) ‖ LP(suite) ‖ canonical_input', () => {
  assert.equal(buildSignedBytes('AB', 'CD', 'EF'), '2:AB2:CDEF');
  assert.equal(
    buildSignedBytes('svrnty:slug-claim:v1', 'ed25519', '{}'),
    '20:svrnty:slug-claim:v17:ed25519{}',
  );
});

test('domain separation: different domain tags ⇒ different signed bytes', () => {
  const input = '{"x":1}';
  assert.notEqual(
    buildSignedBytes(DOMAIN_TRUST_SIGNAL, SUITE_CLASSICAL, input),
    buildSignedBytes(DOMAIN_SLUG_CLAIM, SUITE_CLASSICAL, input),
  );
});

test('suite binding: classical vs hybrid ⇒ different signed bytes (anti-downgrade)', () => {
  const input = '{"x":1}';
  assert.notEqual(
    buildSignedBytes(DOMAIN_TRUST_SIGNAL, SUITE_CLASSICAL, input),
    buildSignedBytes(DOMAIN_TRUST_SIGNAL, SUITE_HYBRID, input),
  );
});

test('framing is injective: split is by LENGTH, never by the ":" delimiter', () => {
  // ("ab","c") vs ("a","bc") must not collide once length-prefixed.
  assert.notEqual(lengthPrefix('ab') + lengthPrefix('c'), lengthPrefix('a') + lengthPrefix('bc'));
  // A tag value that itself contains digits and a colon cannot forge a different (tag,suite) split.
  assert.notEqual(buildSignedBytes('1:x', 'y', 'Z'), buildSignedBytes('1', 'x:y', 'Z'));
});
