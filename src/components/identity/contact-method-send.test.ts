// CUR-1 — contact-method send stub seam tests (no crypto).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  methodKindToWireField,
  sendContactMethodUpdate,
} from './contact-method-send';

test('send stub rejects empty value', async () => {
  const r = await sendContactMethodUpdate({
    kind: 'email',
    value: '   ',
    recipientFingerprints: ['aa'.repeat(20)],
  });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, 'empty-value');
});

test('send stub rejects empty recipients', async () => {
  const r = await sendContactMethodUpdate({
    kind: 'email',
    value: 'a@b.co',
    recipientFingerprints: [],
  });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, 'no-recipients');
});

test('send stub queues honestly without encrypting', async () => {
  const r = await sendContactMethodUpdate({
    kind: 'email',
    value: 'a@b.co',
    recipientFingerprints: ['aa'.repeat(20), 'bb'.repeat(20)],
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.status, 'stub-queued');
    assert.equal(r.queued, 2);
    assert.match(r.message, /not live/i);
  }
});

test('method kind maps toward wire vocab', () => {
  assert.equal(methodKindToWireField('email'), 'emails');
  assert.equal(methodKindToWireField('signal'), 'handles');
  assert.equal(methodKindToWireField('site'), 'urls');
});
