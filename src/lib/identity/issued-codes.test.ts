// src/lib/identity/issued-codes.test.ts
// Run: npx tsx --test src/lib/identity/issued-codes.test.ts
//
// Giver-side issued Grow-code tracking (R1 pending-joiner anti-replay). Pure logic
// only — the IndexedDB wrappers (recordIssuedGrowCode / isOutstandingIssuedCode) are
// thin over the proven 'settings'-store helpers, so the risk lives in the pruning +
// membership math, which is what this pins.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pruneIssuedCodes, isCodeOutstanding, type IssuedCodeMap } from './client-store';

const NOW = 1_000_000_000_000; // fixed "now" in ms
const future = new Date(NOW + 60_000).toISOString();
const past = new Date(NOW - 60_000).toISOString();

test('pruneIssuedCodes keeps live codes, drops expired', () => {
  const map: IssuedCodeMap = { alice: { live: future, dead: past } };
  assert.deepEqual(pruneIssuedCodes(map, NOW), { alice: { live: future } });
});

test('pruneIssuedCodes removes owners left with no live codes', () => {
  const map: IssuedCodeMap = { alice: { dead: past }, bob: { live: future } };
  assert.deepEqual(pruneIssuedCodes(map, NOW), { bob: { live: future } });
});

test('pruneIssuedCodes treats an unparseable expiry as expired (fail-closed)', () => {
  const map: IssuedCodeMap = { alice: { bad: 'not-a-date', live: future } };
  assert.deepEqual(pruneIssuedCodes(map, NOW), { alice: { live: future } });
});

test('pruneIssuedCodes tolerates empty / malformed input', () => {
  assert.deepEqual(pruneIssuedCodes({}, NOW), {});
  assert.deepEqual(pruneIssuedCodes({ alice: {} }, NOW), {});
});

test('isCodeOutstanding: present + live → true', () => {
  assert.equal(isCodeOutstanding({ alice: { c: future } }, 'alice', 'c', NOW), true);
});

test('isCodeOutstanding: present + expired → false', () => {
  assert.equal(isCodeOutstanding({ alice: { c: past } }, 'alice', 'c', NOW), false);
});

test('isCodeOutstanding: missing code / wrong owner / empty map → false', () => {
  assert.equal(isCodeOutstanding({ alice: { c: future } }, 'alice', 'zzz', NOW), false);
  assert.equal(isCodeOutstanding({ alice: { c: future } }, 'bob', 'c', NOW), false);
  assert.equal(isCodeOutstanding({}, 'alice', 'c', NOW), false);
});

test('isCodeOutstanding: unparseable expiry → false (fail-closed)', () => {
  assert.equal(isCodeOutstanding({ alice: { c: 'garbage' } }, 'alice', 'c', NOW), false);
});
