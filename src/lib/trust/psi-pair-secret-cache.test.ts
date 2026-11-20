// The pairwise-secret cache: memory only, copies in and out, emptied when the session locks. Run: npx tsx --test src/lib/trust/psi-pair-secret-cache.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPairSecretCache, PAIR_SECRET_BYTES } from './psi-pair-secret-cache';

const K1 = Uint8Array.from({ length: 32 }, (_, i) => 200 + i);
const K2 = Uint8Array.from({ length: 32 }, (_, i) => 100 + i);
const noHook = (_clear: () => void): void => {};
const secret = (seed: number) => Uint8Array.from({ length: PAIR_SECRET_BYTES }, (_, i) => (seed + i) % 256);

test('a secret set for a contact comes back equal, and an unknown contact has none', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  assert.deepEqual(c.get('c1', K1), secret(1));
  assert.equal(c.get('nobody', K1), undefined);
  assert.equal(c.size(), 1);
});

test('the cache keeps and returns COPIES: changing the caller\'s buffer, or what get returned, changes nothing held', () => {
  const c = createPairSecretCache(noHook);
  const mine = secret(5);
  c.set('c1', K1, mine);
  mine.fill(0);
  assert.deepEqual(c.get('c1', K1), secret(5), 'zeroing the caller\'s buffer did not touch the cache');
  const got = c.get('c1', K1) as Uint8Array;
  got.fill(9);
  assert.deepEqual(c.get('c1', K1), secret(5), 'changing a returned copy did not touch the cache');
});

test('a secret that is not exactly 32 bytes, or an empty contact id, is a programming error', () => {
  const c = createPairSecretCache(noHook);
  for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 'x' as unknown as Uint8Array, [1, 2] as unknown as Uint8Array]) {
    assert.throws(() => c.set('c1', K1, bad), TypeError);
  }
  assert.throws(() => c.set('', K1, secret(1)), TypeError);
  assert.equal(c.size(), 0);
});

test('replacing a contact\'s secret keeps one entry', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  c.set('c1', K1, secret(2));
  assert.equal(c.size(), 1);
  assert.deepEqual(c.get('c1', K1), secret(2));
});

test('clear empties the cache', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  c.set('c2', K1, secret(2));
  c.clear();
  assert.equal(c.size(), 0);
  assert.equal(c.get('c1', K1), undefined);
});

test('NEG: when the session locks (the registered hook fires) the cache is empty', () => {
  let fire: (() => void) | undefined;
  const c = createPairSecretCache((fn) => { fire = fn; });
  assert.ok(fire, 'the cache registered itself for the lock hook');
  c.set('c1', K1, secret(1));
  c.set('c2', K1, secret(2));
  fire!();
  assert.equal(c.size(), 0);
  assert.equal(c.get('c1', K1), undefined);
  c.set('c3', K1, secret(3));
  assert.deepEqual(c.get('c3', K1), secret(3), 'and it is usable again after');
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
  c.set('c1', K1, secret(1));
  const { filled } = recordFilled(() => c.set('c1', K1, secret(2)));
  const zeroed = filled.filter((b) => b.length === PAIR_SECRET_BYTES && b.every((x) => x === 0));
  assert.equal(zeroed.length, 1, 'exactly the old held buffer was zeroed');
});

test('clear zeroes every held buffer before dropping them', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  c.set('c2', K1, secret(2));
  const { filled } = recordFilled(() => c.clear());
  const zeroed = filled.filter((b) => b.length === PAIR_SECRET_BYTES && b.every((x) => x === 0));
  assert.equal(zeroed.length, 2);
});

test('the lock hook is REQUIRED: a cache created without one is refused, not silently left to never clear', () => {
  for (const bad of [undefined, null, 'x', 5, {}]) {
    assert.throws(() => createPairSecretCache(bad as never), TypeError);
  }
});

test('ROTATION: a secret derived under one peer key is NOT served under another, so a rotated-away key\'s secret never survives the rotation', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  assert.equal(c.get('c1', K2), undefined, 'the same contact under a rotated key is a miss');
  c.set('c1', K2, secret(2));
  assert.deepEqual(c.get('c1', K2), secret(2));
  assert.deepEqual(c.get('c1', K1), secret(1), 'the old slot is isolated from the new one');
  assert.equal(c.size(), 2);
});

test('the same peer key under two different contacts is two slots (the contact id is part of the key)', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  assert.equal(c.get('c2', K1), undefined);
});

test('a peer key that is not exactly 32 bytes is a programming error, on get and on set', () => {
  const c = createPairSecretCache(noHook);
  for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 'x' as unknown as Uint8Array, null as unknown as Uint8Array]) {
    assert.throws(() => c.set('c1', bad, secret(1)), TypeError);
    assert.throws(() => c.get('c1', bad), TypeError);
  }
});

test('clear zeroes and drops every slot, rotated ones too', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  c.set('c1', K2, secret(2));
  c.clear();
  assert.equal(c.size(), 0);
  assert.equal(c.get('c1', K1), undefined);
  assert.equal(c.get('c1', K2), undefined);
});

test('keys that differ in a single byte, even the last, are different slots (the whole peer key is part of the key)', () => {
  const c = createPairSecretCache(noHook);
  c.set('c1', K1, secret(1));
  for (const i of [0, 15, 31]) {
    const near = K1.slice();
    near[i] ^= 1;
    assert.equal(c.get('c1', near), undefined, `byte ${i}`);
  }
});
