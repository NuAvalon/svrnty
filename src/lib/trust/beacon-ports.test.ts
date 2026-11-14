// src/lib/trust/beacon-ports.test.ts — #822 (a) S1a: the pair-record store (compare-and-swap, sealed, fail-closed) and the latch (any doubt = 'removed').
// Run: npx tsx --test src/lib/trust/beacon-ports.test.ts
// No IndexedDB: the KV and the sealer are injected fakes. The sealer BINDS the AAD for real (open throws on a different one), so "a blob moved onto
// another pair or owner does not open" is tested by behaviour. The real IndexedDB KV and the session-key sealer are glue, proven separately.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBeaconStore, createBeaconLatch, isPairRecord, type BeaconKV, type Sealer } from './beacon-ports';
import type { PairRecord } from '../crypto/beacon-client';

/** `seed` turns on a deterministic jitter: every get yields a seeded number of ticks, so concurrent callers interleave differently per seed (a lockstep fake can never expose a check-then-act race). */
function fakeKV(seed?: number) {
  const data = new Map<string, string>();
  let st = seed ?? 0;
  const ticks = () => { if (seed === undefined) return 1; st = (st * 1103515245 + 12345) & 0x7fffffff; return 1 + ((st >> 16) % 5); };
  const f = { get: false, swap: false, keys: false, swaps: 0 }; // swaps counts ATTEMPTED writes, so a redundant write is visible even when the value is identical
  const kv: BeaconKV = {
    async get(k) { for (let i = 0, n = ticks(); i < n; i++) await Promise.resolve(); if (f.get) throw new Error('kv get failed'); return data.get(k); },
    async swap(k, expected, next) {
      await Promise.resolve();
      if (f.swap) throw new Error('kv swap failed');
      f.swaps++;
      if (data.get(k) !== expected) return false;
      if (next === undefined) data.delete(k); else data.set(k, next);
      return true;
    },
    async keys(prefix) { await Promise.resolve(); if (f.keys) throw new Error('kv keys failed'); return [...data.keys()].filter((k) => k.startsWith(prefix)); },
  };
  return { kv, data, f };
}

function fakeSealer() {
  const seen: string[] = [];
  const s: Sealer = {
    async seal(aad, value) { seen.push(aad); return Buffer.from(aad + '\u0000' + JSON.stringify(value)).toString('base64'); },
    async open(aad, blob) {
      const txt = Buffer.from(blob, 'base64').toString('utf8');
      const i = txt.indexOf('\u0000');
      if (i < 0 || txt.slice(0, i) !== aad) throw new Error('aad mismatch or malformed');
      return JSON.parse(txt.slice(i + 1));
    },
  };
  return { s, seen };
}

const rec = (pairId: string, version?: number, over: Record<string, unknown> = {}): PairRecord =>
  ({ pairId, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows: [], pendingWithdraws: [], ...(version === undefined ? {} : { version }), ...over }) as PairRecord;
const make = (owner = 'alice', seed?: number) => {
  const { kv, data, f } = fakeKV(seed);
  const { s, seen } = fakeSealer();
  return { kv, data, f, s, seen, store: createBeaconStore(kv, s, owner), latch: createBeaconLatch(kv, s, owner) };
};

// ---------- the pair-record store ----------
test('ST1 absent reads as undefined; the first write is cas(0, version 1); a read returns an equal, independent copy', async () => {
  const { store } = make();
  assert.equal(await store.get('p1'), undefined);
  assert.equal(await store.cas('p1', 0, rec('p1', 1, { observedMatch: true })), true);
  const got = await store.get('p1');
  assert.deepEqual(got, rec('p1', 1, { observedMatch: true }));
  (got as PairRecord).observedMatch = false; // mutating a read must not touch storage
  assert.equal((await store.get('p1'))?.observedMatch, true);
});

test('ST2 compare-and-swap: a stale or wrong expected version loses and changes nothing; the right one wins and the version chain advances', async () => {
  const { store } = make();
  assert.equal(await store.cas('p1', 0, rec('p1', 1, { spentEpochs: ['a'] })), true);
  assert.equal(await store.cas('p1', 0, rec('p1', 1, { spentEpochs: ['x'] })), false, 'a second creator loses');
  assert.equal(await store.cas('p1', 5, rec('p1', 6)), false, 'a wrong expected version loses');
  assert.deepEqual((await store.get('p1'))?.spentEpochs, ['a'], 'losers wrote nothing');
  assert.equal(await store.cas('p1', 1, rec('p1', 2, { spentEpochs: ['a', 'b'] })), true);
  assert.equal((await store.get('p1'))?.version, 2);
});

test('ST3 twenty concurrent first-writers, many differently-interleaved rounds: exactly ONE wins each time, and what is stored is the winner\'s', async () => {
  for (let round = 1; round <= 40; round++) {
    const { store } = make('alice', round);
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => store.cas('race', 0, rec('race', 1, { spentEpochs: ['w' + i] }))));
    assert.equal(results.filter(Boolean).length, 1, `round ${round}`);
    const winner = results.findIndex(Boolean);
    assert.deepEqual((await store.get('race'))?.spentEpochs, ['w' + winner], `round ${round}`);
  }
});

test('ST3b the same race on an EXISTING record: twenty writers all expecting version 1, exactly one moves it to 2', async () => {
  for (let round = 1; round <= 40; round++) {
    const { store } = make('alice', 100 + round);
    await store.cas('race', 0, rec('race', 1));
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => store.cas('race', 1, rec('race', 2, { spentEpochs: ['w' + i] }))));
    assert.equal(results.filter(Boolean).length, 1, `round ${round}`);
    assert.equal((await store.get('race'))?.version, 2);
  }
});

test('ST4 refusals that are bugs, not conflicts, THROW: next.version not expected + 1, a record for another pair, a bad expected version', async () => {
  const { store } = make();
  await assert.rejects(() => store.cas('p1', 0, rec('p1', 5)), /expected \+ 1/);
  await assert.rejects(() => store.cas('p1', 0, rec('p1')), /expected \+ 1/, 'no version at all');
  await assert.rejects(() => store.cas('p1', 0, rec('p2', 1)), /not a record for this pair/);
  await assert.rejects(() => store.cas('p1', -1, rec('p1', 0)), /bad expected version/);
  await assert.rejects(() => store.cas('p1', 1.5, rec('p1', 2.5)), /bad expected version/);
});

test('ST5 plain put is NOT supported: there is no overwrite path', async () => {
  const { store } = make();
  await assert.rejects(() => store.put(rec('p1', 1)), /plain put is not supported/);
  assert.equal(await store.get('p1'), undefined);
});

test('ST6 FAIL-CLOSED: a stored record that cannot be opened or is not a record makes get, cas and pairs THROW; it is never read as absent and never overwritten', async () => {
  const { store, kv, data } = make();
  await store.cas('p1', 0, rec('p1', 1));
  const key = [...data.keys()][0];
  const good = data.get(key)!;
  data.set(key, good.slice(0, -4) + 'AAAA'); // damaged blob
  await assert.rejects(() => store.get('p1'), /cannot be read/);
  await assert.rejects(() => store.cas('p1', 1, rec('p1', 2)), /cannot be read/);
  await assert.rejects(() => store.pairs(), /cannot be read/);
  assert.equal(data.get(key), good.slice(0, -4) + 'AAAA', 'the damaged row was NOT overwritten');
  // a well-formed blob holding something that is not a record
  const s = fakeSealer().s;
  data.set(key, await s.seal('beacon-pair:alice:p1', { hello: 'world' }));
  await assert.rejects(() => store.get('p1'), /cannot be read/);
  await kv.swap(key, data.get(key), undefined);
  assert.equal(await store.get('p1'), undefined, 'once the row is really gone it reads as absent');
});

test('ST7 the AAD binds owner AND pair: a blob moved to another pair\'s key, or read by another owner, does not open', async () => {
  const { store, kv, data, s, seen } = make('alice');
  await store.cas('p1', 0, rec('p1', 1));
  assert.deepEqual(seen, ['beacon-pair:alice:p1'], 'the adapter passes owner and pair into seal');
  const [k1] = [...data.keys()];
  data.set(k1.replace(':p1', ':p2'), data.get(k1)!); // the same blob under pair p2's key
  await assert.rejects(() => store.get('p2'), /cannot be read/);
  const bob = createBeaconStore(kv, s, 'bob');
  data.set(k1.replace(':alice:', ':bob:'), data.get(k1)!); // alice's blob under bob's prefix
  await assert.rejects(() => bob.get('p1'), /cannot be read/);
});

test('ST8 two owners on one device never see each other: separate prefixes, separate pairs() lists', async () => {
  const a = make('alice');
  const bob = createBeaconStore(a.kv, a.s, 'bob');
  await a.store.cas('p1', 0, rec('p1', 1));
  await bob.cas('p1', 0, rec('p1', 1, { observedMatch: true }));
  assert.equal((await a.store.get('p1'))?.observedMatch, false);
  assert.equal((await bob.get('p1'))?.observedMatch, true);
  assert.deepEqual((await a.store.pairs()).map((r) => r.pairId), ['p1']);
  assert.deepEqual((await bob.pairs()).map((r) => r.pairId), ['p1']);
  assert.equal(a.data.size, 2);
});

test('ST9 what reaches storage is the SEALED blob: the raw value holds no plaintext of the record, and pairs() returns every record sorted by pair', async () => {
  const { store, data } = make();
  await store.cas('zz', 0, rec('zz', 1, { spentEpochs: ['marker-epoch'] }));
  await store.cas('aa', 0, rec('aa', 1));
  for (const raw of data.values()) assert.ok(!raw.includes('marker-epoch') && !raw.includes('spentEpochs'), 'no plaintext field names or values in the stored string');
  assert.deepEqual((await store.pairs()).map((r) => r.pairId), ['aa', 'zz']);
});

test('ST10 ids are validated: an owner or pair id with a colon, a slash, a space or nothing at all is refused (a key prefix cannot be confused with another owner)', async () => {
  const { kv, s, store } = make();
  for (const bad of ['', 'a:b', 'a/b', 'a b', 'x'.repeat(129)]) {
    assert.throws(() => createBeaconStore(kv, s, bad), /bad owner/, JSON.stringify(bad));
    await assert.rejects(() => store.get(bad), /bad pairId/, JSON.stringify(bad));
  }
});

test('ST11 storage failures PROPAGATE (never swallowed as absent or as a lost race): a failing get and a failing swap both throw', async () => {
  const m = make();
  await m.store.cas('p1', 0, rec('p1', 1));
  m.f.get = true;
  await assert.rejects(() => m.store.get('p1'), /kv get failed/);
  m.f.get = false; m.f.swap = true;
  await assert.rejects(() => m.store.cas('p1', 1, rec('p1', 2)), /kv swap failed/);
  m.f.swap = false; m.f.keys = true;
  await assert.rejects(() => m.store.pairs(), /kv keys failed/);
});

test('ST12 isPairRecord: rejects a missing field, a wrong type, a negative or fractional version, a bad tap, and another pair\'s record', () => {
  assert.equal(isPairRecord(rec('p1', 0), 'p1'), true);
  assert.equal(isPairRecord(rec('p1', 3, { tap: { gen: 2, trust: true } }), 'p1'), true);
  assert.equal(isPairRecord(rec('p1', 1), 'p2'), false);
  for (const bad of [null, [], 'x', 1, {}, { ...rec('p1', 1), observedMatch: 'yes' }, { ...rec('p1', 1), spentEpochs: [1] }, { ...rec('p1', 1), rows: {} },
    { ...rec('p1', 1), version: -1 }, { ...rec('p1', 1), version: 1.5 }, { ...rec('p1', 1), tap: { gen: -1, trust: true } }, { ...rec('p1', 1), tap: { gen: 1, trust: 1 } }]) {
    assert.equal(isPairRecord(bad), false, JSON.stringify(bad));
  }
});

// ---------- the latch ----------
test('LT1 no latch reads null; setLatched(local) reads removed; the two sources narrow independently; isLatched is kindOf !== null', async () => {
  const { latch } = make();
  assert.equal(await latch.kindOf('p1'), null);
  assert.equal(await latch.isLatched('p1'), false);
  await latch.setLatched('p1', 'local');
  assert.equal(await latch.kindOf('p1'), 'removed');
  assert.equal(await latch.kindOf('p1', 'local'), 'removed');
  assert.equal(await latch.kindOf('p1', 'remote'), null);
  assert.equal(await latch.isLatched('p1'), true);
  await latch.setLatched('p2', 'remote');
  assert.equal(await latch.kindOf('p2', 'local'), null);
  assert.equal(await latch.kindOf('p2', 'remote'), 'removed');
  assert.equal(await latch.kindOf('p2'), 'removed', 'either side removed = removed');
});

test('LT2 clearLatched clears ONLY that source, is idempotent, and a pair latched on both sides stays latched until both are cleared', async () => {
  const { latch } = make();
  await latch.setLatched('p1', 'local');
  await latch.setLatched('p1', 'remote');
  await latch.clearLatched('p1', 'local');
  assert.equal(await latch.kindOf('p1', 'local'), null);
  assert.equal(await latch.kindOf('p1', 'remote'), 'removed');
  assert.equal(await latch.isLatched('p1'), true);
  await latch.clearLatched('p1', 'local'); // again: no throw
  await latch.clearLatched('p1', 'remote');
  assert.equal(await latch.isLatched('p1'), false);
});

test('LT3 setLatched is idempotent (one write) and UPGRADES a frozen row to removed; removed dominates frozen across sources', async () => {
  const { latch, kv, data, s, f } = make();
  await latch.setLatched('p1', 'local');
  const once = [...data.entries()], writes = f.swaps;
  await latch.setLatched('p1', 'local');
  assert.deepEqual([...data.entries()], once, 'a second set changes nothing');
  assert.equal(f.swaps, writes, 'and does not even attempt a write');
  // a frozen row written by a future freeze feature, via the same sealer and key shape
  await kv.swap('beacon_latch:alice:remote:p2', undefined, await s.seal('beacon-latch:alice:remote:p2', { v: 1, kind: 'frozen' }));
  assert.equal(await latch.kindOf('p2'), 'frozen');
  assert.equal(await latch.kindOf('p2', 'remote'), 'frozen');
  await latch.setLatched('p2', 'local');
  assert.equal(await latch.kindOf('p2'), 'removed', 'removed on one side dominates frozen on the other');
  await latch.setLatched('p2', 'remote');
  assert.equal(await latch.kindOf('p2', 'remote'), 'removed', 'a frozen row is upgraded');
});

test('LT4 FAIL-CLOSED: an unreadable, unknown-kind, wrong-version or wrongly-bound row reads as removed; so does a failing storage read', async () => {
  const m = make();
  const { latch, kv, data, s } = m;
  const key = 'beacon_latch:alice:local:p1';
  data.set(key, '%%%not-a-blob%%%');
  assert.equal(await latch.kindOf('p1', 'local'), 'removed', 'garbage');
  data.set(key, await s.seal('beacon-latch:alice:local:p1', { v: 1, kind: 'weird' }));
  assert.equal(await latch.kindOf('p1', 'local'), 'removed', 'unknown kind');
  data.set(key, await s.seal('beacon-latch:alice:local:p1', { v: 2, kind: 'frozen' }));
  assert.equal(await latch.kindOf('p1', 'local'), 'removed', 'unknown version');
  data.set(key, await s.seal('beacon-latch:alice:remote:p1', { v: 1, kind: 'frozen' }));
  assert.equal(await latch.kindOf('p1', 'local'), 'removed', 'a blob sealed for another source does not open here');
  await kv.swap(key, data.get(key), undefined);
  assert.equal(await latch.kindOf('p1'), null);
  m.f.get = true;
  assert.equal(await latch.kindOf('p1'), 'removed', 'a storage read failure is a doubt, so removed');
  assert.equal(await latch.isLatched('p1'), true);
});

test('LT5 a failing storage WRITE throws: the latch never pretends to be set', async () => {
  const m = make();
  m.f.swap = true;
  await assert.rejects(() => m.latch.setLatched('p1', 'local'), /kv swap failed/);
  await assert.rejects(async () => { m.f.swap = false; await m.latch.setLatched('p1', 'local'); m.f.swap = true; await m.latch.clearLatched('p1', 'local'); }, /kv swap failed/);
});

test('LT6 latch rows are sealed with an AAD that binds owner, source and pair, and two owners do not share a latch', async () => {
  const m = make('alice');
  await m.latch.setLatched('p1', 'local');
  assert.deepEqual(m.seen, ['beacon-latch:alice:local:p1']);
  const bob = createBeaconLatch(m.kv, m.s, 'bob');
  assert.equal(await bob.kindOf('p1'), null, 'bob has no latch on alice\'s pair id');
  for (const raw of m.data.values()) assert.ok(!raw.includes('removed') && !raw.includes('"kind"'), 'no plaintext kind in the stored string');
});

/** A sealer whose session can be locked: while locked, seal AND open throw, as the real session-key sealer does with no key. */
function lockableSealer() {
  const { s: inner } = fakeSealer();
  const st = { locked: false };
  const wrap: Sealer = {
    async seal(aad, value) { if (st.locked) throw new Error('session locked'); return inner.seal(aad, value); },
    async open(aad, blob) { if (st.locked) throw new Error('session locked'); return inner.open(aad, blob); },
  };
  return { wrap, inner, st };
}

test('LT7 a Block over a row the latch cannot OPEN never reports success: locked, setLatched over a frozen row THROWS and writes nothing; after unlock the row is still frozen', async () => {
  const { kv, data, f } = fakeKV();
  const { wrap, inner, st } = lockableSealer();
  const latch = createBeaconLatch(kv, wrap, 'alice');
  const key = 'beacon_latch:alice:local:p1';
  const frozen = await inner.seal('beacon-latch:alice:local:p1', { v: 1, kind: 'frozen' });
  data.set(key, frozen);
  st.locked = true;
  const before = f.swaps;
  await assert.rejects(latch.setLatched('p1', 'local'), /locked/, 'a Block while locked over an unopenable row must fail, never return ok');
  assert.equal(f.swaps, before, 'it attempted no write');
  assert.equal(data.get(key), frozen, 'the stored row is untouched');
  assert.equal(await latch.kindOf('p1', 'local'), 'removed', 'while locked a READ is still the fail-closed answer');
  st.locked = false;
  assert.equal(await latch.kindOf('p1', 'local'), 'frozen', 'after unlock the row still says frozen: the Block did not pretend to land');
  await latch.setLatched('p1', 'local');
  assert.equal(await latch.kindOf('p1', 'local'), 'removed', 'an unlocked set upgrades it');
});

test('LT8 a row that cannot be understood (garbage, unknown kind, unknown version, bound to another source) is REPLACED by a fresh removed row when the session is open; it is not mistaken for already-removed', async () => {
  const aad = 'beacon-latch:alice:local:p1';
  const key = 'beacon_latch:alice:local:p1';
  const plants: Array<[string, (s: Sealer) => Promise<string>]> = [
    ['garbage', async () => '%%%not-a-blob%%%'],
    ['unknown kind', (s) => s.seal(aad, { v: 1, kind: 'weird' })],
    ['unknown version', (s) => s.seal(aad, { v: 2, kind: 'frozen' })],
    ['sealed for another source', (s) => s.seal('beacon-latch:alice:remote:p1', { v: 1, kind: 'frozen' })],
  ];
  for (const [label, plant] of plants) {
    const { data, f, s, latch } = make();
    data.set(key, await plant(s));
    const before = f.swaps;
    await latch.setLatched('p1', 'local');
    assert.equal(f.swaps, before + 1, `${label}: a write was made`);
    assert.deepEqual(await s.open(aad, data.get(key)!), { v: 1, kind: 'removed' }, `${label}: the row now OPENS and says removed (not merely "reads as removed because it is garbage")`);
    assert.equal(await latch.kindOf('p1', 'local'), 'removed', label);
  }
});
