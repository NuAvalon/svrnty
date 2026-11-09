// Run: npx tsx --test src/lib/identity/save-owner-email.test.ts
// The identity record is one blob, so saving one field rewrites all of it. The base must be what is stored, not a copy in memory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { saveOwnerEmail } from './save-owner-email';

function fake(stored: unknown) {
  const writes: Array<[string, unknown]> = [];
  return { writes, deps: { load: async (_fp: string) => stored, store: async (fp: string, v: unknown) => { writes.push([fp, v]); } } };
}

// Frozen, so an implementation that edits what it was handed throws here instead of quietly changing the fixture for later tests.
function deepFreeze<T>(o: T): T {
  if (o && typeof o === 'object') { Object.values(o).forEach(deepFreeze); Object.freeze(o); }
  return o;
}

const STORED = deepFreeze({ identity: { fingerprint: 'F', email: 'old@x', name: 'New Name' }, card_version: 7, device_mailbox: { k: 1 } });
const STALE = deepFreeze({ identity: { fingerprint: 'F', email: 'older@x', name: 'Old Name' } });

test('keeps the card version the in-memory copy does not have', async () => {
  const { deps, writes } = fake(STORED);
  await saveOwnerEmail('F', 'new@x', STALE, deps);
  assert.equal((writes[0][1] as { card_version: number }).card_version, 7);
});

test('keeps every other stored field the copy lacks, and stored values beat stale ones', async () => {
  const { deps, writes } = fake(STORED);
  await saveOwnerEmail('F', 'new@x', STALE, deps);
  assert.deepEqual(writes[0][1], { identity: { fingerprint: 'F', email: 'new@x', name: 'New Name' }, card_version: 7, device_mailbox: { k: 1 } });
});

test('writes once, to that fingerprint, and returns exactly what it wrote', async () => {
  const { deps, writes } = fake(STORED);
  const next = await saveOwnerEmail('F', 'new@x', STALE, deps);
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], 'F');
  assert.equal(writes[0][1], next);
});

test('changes neither the stored object nor the copy it was given', async () => {
  const stored = structuredClone(STORED);
  const copy = structuredClone(STALE);
  const { deps } = fake(stored);
  await saveOwnerEmail('F', 'new@x', copy, deps);
  assert.deepEqual(stored, STORED);
  assert.deepEqual(copy, STALE);
});

for (const nothing of [null, undefined]) {
  test(`with nothing stored (${nothing}) the copy is the base, as before`, async () => {
    const { deps, writes } = fake(nothing);
    await saveOwnerEmail('F', 'new@x', STALE, deps);
    assert.deepEqual(writes[0][1], { identity: { fingerprint: 'F', email: 'new@x', name: 'Old Name' } });
  });
}

test('a failed read writes nothing', async () => {
  const writes: unknown[] = [];
  await assert.rejects(saveOwnerEmail('F', 'new@x', STALE, {
    load: async () => { throw new Error('locked'); },
    store: async (_f: string, v: unknown) => { writes.push(v); },
  }), /locked/);
  assert.equal(writes.length, 0);
});

test('a failed write is not swallowed', async () => {
  await assert.rejects(saveOwnerEmail('F', 'new@x', STALE, {
    load: async () => STORED,
    store: async () => { throw new Error('quota'); },
  }), /quota/);
});
