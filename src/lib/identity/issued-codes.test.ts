// src/lib/identity/issued-codes.test.ts
// Run: npx tsx --test src/lib/identity/issued-codes.test.ts
//
// Giver-side issued Grow-code accept-oracle (R1 pending-joiner, MULTI-USE per
// Flint #125359). Pure logic only — the async wrappers (recordIssuedGrowCode /
// recordAcceptedJoiner / loadIssuedCodeMap) are thin over the proven 'settings'
// store, so the risk lives in the pruning + acceptance-window + cap + accepted-set
// math, which is what this pins.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  pruneIssuedCodes,
  isCodeOutstanding,
  codeUnderCap,
  alreadyAccepted,
  markAcceptedInMap,
  type IssuedCodeMap,
} from './client-store';

const NOW = 1_000_000_000_000; // fixed "now" in ms
const future = NOW + 60_000;
const past = NOW - 60_000;
const entry = (acceptUntil: number, accepted: string[] = []) => ({ acceptUntil, accepted });

test('pruneIssuedCodes keeps in-window entries, drops expired', () => {
  const map: IssuedCodeMap = { alice: { live: entry(future, ['j1']), dead: entry(past) } };
  assert.deepEqual(pruneIssuedCodes(map, NOW), { alice: { live: entry(future, ['j1']) } });
});

test('pruneIssuedCodes removes owners left with no live entries', () => {
  const map: IssuedCodeMap = { alice: { dead: entry(past) }, bob: { live: entry(future) } };
  assert.deepEqual(pruneIssuedCodes(map, NOW), { bob: { live: entry(future) } });
});

test('pruneIssuedCodes normalizes malformed entries (fail-closed)', () => {
  const map = { alice: { bad: { acceptUntil: 'nope' } as any, live: entry(future) } } as IssuedCodeMap;
  assert.deepEqual(pruneIssuedCodes(map, NOW), { alice: { live: entry(future) } });
});

test('pruneIssuedCodes defaults a missing accepted[] to []', () => {
  const map = { alice: { c: { acceptUntil: future } as any } } as IssuedCodeMap;
  assert.deepEqual(pruneIssuedCodes(map, NOW), { alice: { c: entry(future, []) } });
});

test('isCodeOutstanding: in-window true; expired / missing code / wrong owner false', () => {
  const map: IssuedCodeMap = { alice: { c: entry(future), d: entry(past) } };
  assert.equal(isCodeOutstanding(map, 'alice', 'c', NOW), true);
  assert.equal(isCodeOutstanding(map, 'alice', 'd', NOW), false);
  assert.equal(isCodeOutstanding(map, 'alice', 'zzz', NOW), false);
  assert.equal(isCodeOutstanding(map, 'bob', 'c', NOW), false);
});

test('codeUnderCap: under cap true, at cap false, missing false', () => {
  const map: IssuedCodeMap = { alice: { c: entry(future, ['j1', 'j2']) } };
  assert.equal(codeUnderCap(map, 'alice', 'c', 7), true);
  assert.equal(codeUnderCap(map, 'alice', 'c', 2), false); // 2 accepted, cap 2 → not under
  assert.equal(codeUnderCap(map, 'alice', 'zzz', 7), false);
});

test('alreadyAccepted: present joiner true, absent false', () => {
  const map: IssuedCodeMap = { alice: { c: entry(future, ['j1']) } };
  assert.equal(alreadyAccepted(map, 'alice', 'c', 'j1'), true);
  assert.equal(alreadyAccepted(map, 'alice', 'c', 'j2'), false);
  assert.equal(alreadyAccepted(map, 'alice', 'zzz', 'j1'), false);
});

test('markAcceptedInMap: adds new joiner, idempotent, no-op on missing code', () => {
  const map: IssuedCodeMap = { alice: { c: entry(future, ['j1']) } };
  markAcceptedInMap(map, 'alice', 'c', 'j2');
  assert.deepEqual(map.alice.c.accepted, ['j1', 'j2']);
  markAcceptedInMap(map, 'alice', 'c', 'j2'); // idempotent — no duplicate
  assert.deepEqual(map.alice.c.accepted, ['j1', 'j2']);
  markAcceptedInMap(map, 'alice', 'zzz', 'j3'); // missing code → no throw, no create
  assert.equal(map.alice.zzz, undefined);
});

test('multi-use accept flow: distinct joiners accumulate, cap enforced, replay blocked', () => {
  const map: IssuedCodeMap = { alice: { link: entry(future, []) } };
  const cap = 3;
  const canAccept = (joiner: string) =>
    isCodeOutstanding(map, 'alice', 'link', NOW) &&
    codeUnderCap(map, 'alice', 'link', cap) &&
    !alreadyAccepted(map, 'alice', 'link', joiner);
  for (const j of ['j1', 'j2', 'j3']) {
    assert.equal(canAccept(j), true);
    markAcceptedInMap(map, 'alice', 'link', j);
  }
  assert.equal(canAccept('j4'), false); // cap reached → 4th distinct joiner refused
  assert.equal(canAccept('j1'), false); // replay of an already-accepted joiner
});

test('expired code refuses accepts even under cap', () => {
  const map: IssuedCodeMap = { alice: { link: entry(past, []) } };
  const canAccept = (joiner: string) =>
    isCodeOutstanding(map, 'alice', 'link', NOW) &&
    codeUnderCap(map, 'alice', 'link', 7) &&
    !alreadyAccepted(map, 'alice', 'link', joiner);
  assert.equal(canAccept('j1'), false);
});
