// The pairwise-secret cache: memory only, copies in and out, emptied when the session locks. Run: npx tsx --test src/lib/trust/psi-pair-secret-cache.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPairSecretCache, PAIR_SECRET_BYTES } from './psi-pair-secret-cache';

const noHook = (_clear: () => void): void => {};
const secret = (seed: number) => Uint8Array.from({ length: PAIR_SECRET_BYTES }, (_, i) => (seed + i) % 256);

test('a secret set for a contact comes back equal, and an unknown contact has none', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', secret(1));
  assert.deepEqual(c.get('c1'), secret(1));
  assert.equal(c.get('nobody'), undefined);
  assert.equal(c.size(), 1);
});

test('the cache keeps and returns COPIES: changing the caller\'s buffer, or what get returned, changes nothing held', () => {
  const c = createPairSecretCache(noHook);
  const mine = secret(5);
  c.set('c1', mine);
  mine.fill(0);
  assert.deepEqual(c.get('c1'), secret(5), 'zeroing the caller\'s buffer did not touch the cache');
  const got = c.get('c1') as Uint8Array;
  got.fill(9);
  assert.deepEqual(c.get('c1'), secret(5), 'changing a returned copy did not touch the cache');
});

test('a secret that is not exactly 32 bytes, or an empty contact id, is a programming error', () => {
  const c = createPairSecretCache(noHook);
  for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 'x' as unknown as Uint8Array, [1, 2] as unknown as Uint8Array]) {
    assert.throws(() => c.set('c1', bad), TypeError);
  }
  assert.throws(() => c.set('', secret(1)), TypeError);
  assert.equal(c.size(), 0);
});

test('replacing a contact\'s secret keeps one entry', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', secret(1));
  c.set('c1', secret(2));
  assert.equal(c.size(), 1);
  assert.deepEqual(c.get('c1'), secret(2));
});

test('clear empties the cache', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', secret(1));
  c.set('c2', secret(2));
  c.clear();
  assert.equal(c.size(), 0);
  assert.equal(c.get('c1'), undefined);
});

test('NEG: when the session locks (the registered hook fires) the cache is empty', () => {
  let fire: (() => void) | undefined;
  const c = createPairSecretCache((fn) => { fire = fn; });
  assert.ok(fire, 'the cache registered itself for the lock hook');
  c.set('c1', secret(1));
  c.set('c2', secret(2));
  fire!();
  assert.equal(c.size(), 0);
  assert.equal(c.get('c1'), undefined);
  c.set('c3', secret(3));
  assert.deepEqual(c.get('c3'), secret(3), 'and it is usable again after');
});

test('GUARD: the module reads and writes no storage and imports nothing from the store', () => {
  const src = readFileSync(new URL('./psi-pair-secret-cache.ts', import.meta.url), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(src, /\bimport\b/, 'no imports at all');
  assert.doesNotMatch(src, /indexedDB|localStorage|sessionStorage|\bpostMessage\b|\bfetch\b|JSON\.stringify|txPut|writeFile/, 'no storage, no network, no serialisation');
});

// The cache hands out copies, so the bytes it zeroes cannot be seen through its API. Record the buffers `fill` is called on, run the operation, and
// check that the buffer the cache held is all zero afterwards.
function recordFilled<T>(fn: () => T): { filled: Uint8Array[]; result: T } {
  const filled: Uint8Array[] = [];
  const original = Uint8Array.prototype.fill;
  Uint8Array.prototype.fill = function (this: Uint8Array, ...args: Parameters<Uint8Array['fill']>) {
    filled.push(this);
    return original.apply(this, args);
  } as Uint8Array['fill'];
  try {
    return { filled, result: fn() };
  } finally {
    Uint8Array.prototype.fill = original;
  }
}

test('replacing a contact\'s secret zeroes the old held bytes', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', secret(1));
  const { filled } = recordFilled(() => c.set('c1', secret(2)));
  const zeroed = filled.filter((b) => b.length === PAIR_SECRET_BYTES && b.every((x) => x === 0));
  assert.equal(zeroed.length, 1, 'exactly the old held buffer was zeroed');
});

test('clear zeroes every held buffer before dropping them', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', secret(1));
  c.set('c2', secret(2));
  const { filled } = recordFilled(() => c.clear());
  const zeroed = filled.filter((b) => b.length === PAIR_SECRET_BYTES && b.every((x) => x === 0));
  assert.equal(zeroed.length, 2);
});

test('the lock hook is REQUIRED: a cache created without one is refused, not silently left to never clear', () => {
  for (const bad of [undefined, null, 'x', 5, {}]) {
    assert.throws(() => createPairSecretCache(bad as never), TypeError);
  }
});
