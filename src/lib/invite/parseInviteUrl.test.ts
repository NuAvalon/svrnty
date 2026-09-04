// src/lib/invite/parseInviteUrl.test.ts
// INV-4 host-pin + TOTAL parse. Run: npx tsx --test src/lib/invite/parseInviteUrl.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseInviteUrl } from './parseInviteUrl';

test('accepts a known-host invite with a key fragment', () => {
  const p = parseInviteUrl('https://svrnty.is/c/AbC-_9#keymaterial');
  assert.deepEqual(p, { code: 'AbC-_9', keyFragment: 'keymaterial' });
});

test('accepts a scheme-less known-host paste', () => {
  const p = parseInviteUrl('svrnty.is/c/abc#k');
  assert.deepEqual(p, { code: 'abc', keyFragment: 'k' });
});

test('rejects off-host, missing key, bad path, and non-strings — TOTAL, no throw', () => {
  const bad = [
    'https://evil.example/c/abc#k',
    'https://svrnty.is/c/abc',
    'https://svrnty.is/join/abc#k',
    'https://svrnty.is/c/abc#',
    '',
    1,
    null,
  ];
  for (const input of bad) {
    assert.equal(parseInviteUrl(input), null);
  }
});
