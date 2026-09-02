// src/lib/contacts/method-send-delta.test.ts
// Run: npx tsx --test src/lib/contacts/method-send-delta.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildMethodDelta } from './method-send-delta';

test('handle-kind → handles MERGE carrying only the changed sub-key', () => {
  assert.deepEqual(buildMethodDelta('signal', '@alice.99'), { handles: { signal: '@alice.99' } });
  assert.deepEqual(buildMethodDelta('telegram', '@a'), { handles: { telegram: '@a' } });
});

test("clearing a handle sends '' (delete sentinel, NOT null; trimmed)", () => {
  assert.deepEqual(buildMethodDelta('signal', ''), { handles: { signal: '' } });
  assert.deepEqual(buildMethodDelta('signal', '   '), { handles: { signal: '' } });
});

test('email / phone → REPLACE list (single primary)', () => {
  assert.deepEqual(buildMethodDelta('email', 'a@b.com'), { emails: ['a@b.com'] });
  assert.deepEqual(buildMethodDelta('phone', '+15551234567'), { phones: ['+15551234567'] });
});

test('site / website → urls REPLACE', () => {
  assert.deepEqual(buildMethodDelta('site', 'https://x.example'), { urls: ['https://x.example'] });
  assert.deepEqual(buildMethodDelta('website', 'https://y.example'), { urls: ['https://y.example'] });
});

test('clearing a list field → empty list', () => {
  assert.deepEqual(buildMethodDelta('email', ''), { emails: [] });
  assert.deepEqual(buildMethodDelta('site', ''), { urls: [] });
});

test('unknown kind fails loud (never a silent empty/mis-shaped delta)', () => {
  assert.throws(() => buildMethodDelta('myspace', 'x'));
});

test('every curated handle key routes to handles (shared set, no drift)', async () => {
  const { CONTACT_HANDLE_KEYS } = await import('../trust/contact-update');
  for (const k of CONTACT_HANDLE_KEYS) {
    const d = buildMethodDelta(k, 'v') as { handles?: Record<string, string> };
    assert.ok(d.handles && d.handles[k] === 'v', `${k} → handles.${k}`);
  }
});
