import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  contactHasDistress,
  DISTRESS_COPY,
  distressWentPersistPatch,
  sendDistress,
} from './distress';
import { stripOwnerLocalForPublish } from './trust-recipe';

test('inbound mark is a witnessed receipt, not a badge', () => {
  assert.equal(contactHasDistress({}), false);
  assert.equal(contactHasDistress({ distress_inbound: true }), true);
  assert.equal(contactHasDistress({ metadata: { distress_inbound: true } }), true);
  assert.equal(contactHasDistress({ metadata: { distress_inbound: false } }), false);
});

test('I went clears the mark on this device only', () => {
  const patch = distressWentPersistPatch({ notes: 'stay' });
  assert.equal(patch.distress_inbound, false);
  assert.equal(patch.metadata.distress_inbound, false);
  assert.equal((patch.metadata as { notes?: string }).notes, 'stay');
});

test('sendDistress is silent — no sent receipt', async () => {
  await sendDistress({ recipientFingerprints: ['aa'] });
  assert.doesNotMatch(DISTRESS_COPY.silent, /sent/i);
  assert.doesNotMatch(DISTRESS_COPY.caution, /sent/i);
  assert.doesNotMatch(DISTRESS_COPY.went, /sent/i);
});

test('inbound distress does not publish', () => {
  const stripped = stripOwnerLocalForPublish({
    fingerprint: 'aa',
    distress_inbound: true,
    open_visibility: true,
    metadata: {
      distress_inbound: true,
      notes: 'x',
      open_visibility: true,
      share_settings: { open_visibility: true },
    },
  });
  assert.equal('distress_inbound' in stripped, false);
  assert.equal('open_visibility' in stripped, false);
  const m = stripped.metadata as Record<string, unknown>;
  assert.equal('distress_inbound' in m, false);
  assert.equal('open_visibility' in m, false);
});
