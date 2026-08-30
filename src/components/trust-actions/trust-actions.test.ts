/**
 * Unit tests for CUR-5 trust-action copy + apply seam (no crypto).
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  applyTrustAction,
  getTrustActionCopy,
  isContactBlocked,
  safeDisplayName,
  type TrustActionLocalPatch,
  type TrustActionTarget,
} from './trust-actions';

const alice: TrustActionTarget = {
  id: 'c1',
  fingerprint: 'abc',
  name: 'Alice',
  trusted: false,
};

test('safeDisplayName strips controls and bounds length', () => {
  assert.equal(safeDisplayName('  Ada\u0000 Lovelace  '), 'Ada Lovelace');
  assert.equal(safeDisplayName(''), 'this contact');
  assert.ok(safeDisplayName('x'.repeat(100)).endsWith('…'));
});

test('trust copy is binary and does not invent scores', () => {
  const copy = getTrustActionCopy('trust', alice);
  assert.match(copy.body, /binary/i);
  assert.match(copy.body, /no score or rank/i);
  assert.doesNotMatch(copy.body, /percent|tier|reputation/i);
  assert.equal(copy.danger, false);
});

test('break copy is honest about local-only today', () => {
  const copy = getTrustActionCopy('break', { ...alice, trusted: true });
  assert.match(copy.body, /local book/i);
  assert.equal(copy.danger, true);
  assert.equal(copy.reasonOptional, true);
});

test('block copy asserts relay stays blind', () => {
  const copy = getTrustActionCopy('block', alice);
  assert.match(copy.body, /relay stays blind/i);
  assert.match(copy.body, /Local only/i);
});

test('applyTrustAction trust writes local patch', async () => {
  const patches: TrustActionLocalPatch[] = [];
  const result = await applyTrustAction('trust', alice, {
    applyLocal: async (p) => {
      patches.push(p);
    },
  });
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.wire, 'stub-not-live');
    assert.equal(result.local, 'applied');
  }
  assert.equal(patches[0]?.kind, 'trust');
  if (patches[0]?.kind === 'trust') {
    assert.equal(patches[0].trusted, true);
    assert.equal(patches[0].trust_level, 'trusted');
  }
});

test('applyTrustAction break rejects when not trusted', async () => {
  const result = await applyTrustAction('break', alice, {
    applyLocal: async () => {},
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'not-trusted');
});

test('applyTrustAction block clears trust and sets blocked', async () => {
  const patches: TrustActionLocalPatch[] = [];
  const result = await applyTrustAction(
    'block',
    { ...alice, trusted: true },
    {
      applyLocal: async (p) => {
        patches.push(p);
      },
    }
  );
  assert.equal(result.ok, true);
  assert.equal(patches[0]?.kind, 'block');
  if (patches[0]?.kind === 'block') {
    assert.equal(patches[0].blocked, true);
    assert.equal(patches[0].trusted, false);
  }
});

test('applyTrustAction remove', async () => {
  let removed = false;
  const result = await applyTrustAction('remove', alice, {
    applyLocal: async (p) => {
      if (p.kind === 'remove') removed = true;
    },
  });
  assert.equal(result.ok, true);
  assert.equal(removed, true);
});

test('isContactBlocked reads open-bag shapes', () => {
  assert.equal(isContactBlocked({ blocked: true }), true);
  assert.equal(isContactBlocked({ metadata: { blocked: true } }), true);
  assert.equal(isContactBlocked({}), false);
});
