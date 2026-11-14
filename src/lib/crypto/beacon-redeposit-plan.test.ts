/* eslint-disable @typescript-eslint/no-explicit-any -- test doubles and deliberately wrong inputs */
// src/lib/crypto/beacon-redeposit-plan.test.ts
// #588 piece D (pure planning half): WHEN is each pending trust's weekly deposit due? Jitter is derived from the identity's secret (identity state, not per device), trust id and epoch, so
// a reload does not re-roll the time (and a restart burst would be a timing signal). Run: npx tsx --test src/lib/crypto/beacon-redeposit-plan.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planDeposits, currentEpoch, depositKey } from './beacon-redeposit-plan';
import * as wire from './beacon-wire.mjs';

const EPOCH = (wire as any).EPOCH_SECONDS as number, GRACE = (wire as any).GRACE_SECONDS as number;
const seed = (n: number) => new Uint8Array(32).fill(n);
const epochStartMs = (e: number) => e * EPOCH * 1000;
const E = 2900;

test('P1 currentEpoch = floor(unix seconds / EPOCH_SECONDS), at the boundaries', () => {
  assert.equal(currentEpoch(epochStartMs(E)), E);
  assert.equal(currentEpoch(epochStartMs(E) - 1), E - 1);
  assert.equal(currentEpoch(epochStartMs(E) + EPOCH * 1000 - 1), E);
  assert.equal(currentEpoch(epochStartMs(E + 1)), E + 1);
});

test('P2 the due time is DETERMINISTIC for (seed, trust, epoch): two plans made at different moments agree', async () => {
  const a = await planDeposits({ nowMs: epochStartMs(E) + 10, trusts: ['t1'], done: new Set(), seed: seed(1) });
  const b = await planDeposits({ nowMs: epochStartMs(E) + 999_000, trusts: ['t1'], done: new Set(), seed: seed(1) });
  const dueA = a.due.length ? a.due[0].dueAtMs : a.nextAtMs;
  const dueB = b.due.length ? b.due[0].dueAtMs : b.nextAtMs;
  assert.ok(dueA !== null && dueA === dueB);
});

test('P3 every due time lies strictly inside the epoch and at least one grace window from BOTH edges (never at a boundary)', async () => {
  for (let i = 0; i < 300; i++) {
    const s = new Uint8Array(32); s[0] = i & 255; s[1] = i >> 8;
    const p = await planDeposits({ nowMs: epochStartMs(E), trusts: ['t' + i], done: new Set(), seed: s });
    const at = p.due.length ? p.due[0].dueAtMs : (p.nextAtMs as number);
    assert.ok(at >= epochStartMs(E) + GRACE * 1000, 'not inside the opening grace window');
    assert.ok(at < epochStartMs(E + 1) - GRACE * 1000 + 1, 'not inside the closing grace window');
  }
});

test('P4 nothing is due before its time; it becomes due exactly at it; nextAtMs is the earliest FUTURE due time', async () => {
  const t0 = await planDeposits({ nowMs: epochStartMs(E), trusts: ['a', 'b'], done: new Set(), seed: seed(2) });
  assert.equal(t0.due.length, 0, 'at the epoch start the opening grace window means nothing is due');
  assert.ok(typeof t0.nextAtMs === 'number');
  const at = t0.nextAtMs as number;
  const before = await planDeposits({ nowMs: at - 1, trusts: ['a', 'b'], done: new Set(), seed: seed(2) });
  assert.equal(before.due.length, 0);
  const on = await planDeposits({ nowMs: at, trusts: ['a', 'b'], done: new Set(), seed: seed(2) });
  assert.ok(on.due.length >= 1);
  assert.deepEqual(on.due.map((d) => d.epoch), on.due.map(() => E));
});

test('P5 a trust already deposited for this epoch is skipped; the next epoch is a fresh job', async () => {
  const done = new Set([depositKey('a', E)]);
  const late = epochStartMs(E) + (EPOCH - GRACE - 1) * 1000;
  const p = await planDeposits({ nowMs: late, trusts: ['a', 'b'], done, seed: seed(3) });
  assert.ok(!p.due.some((d) => d.trustId === 'a'));
  const nextEpoch = await planDeposits({ nowMs: epochStartMs(E + 1) + 5, trusts: ['a'], done, seed: seed(3) });
  assert.equal(nextEpoch.due.length + (nextEpoch.nextAtMs === null ? 0 : 1) >= 1, true, 'epoch E+1 is not covered by the E record');
});

test('P6 late catch-up: if the app was closed past the due time, it is due NOW in the same epoch (once), not skipped', async () => {
  const p0 = await planDeposits({ nowMs: epochStartMs(E), trusts: ['c'], done: new Set(), seed: seed(4) });
  const at = p0.nextAtMs as number;
  const p = await planDeposits({ nowMs: at + 3_600_000, trusts: ['c'], done: new Set(), seed: seed(4) });
  assert.equal(p.due.length, 1);
  assert.equal(p.due[0].trustId, 'c');
});

test('P7 different trusts and different epochs get different offsets (no shared fixed offset), and the offsets spread across the window', async () => {
  const offs = new Set<number>();
  const bins = new Array(10).fill(0);
  const span = (EPOCH - 2 * GRACE) * 1000;
  for (let i = 0; i < 2000; i++) {
    const p = await planDeposits({ nowMs: epochStartMs(E), trusts: ['t' + i], done: new Set(), seed: seed(5) });
    const off = (p.nextAtMs as number) - (epochStartMs(E) + GRACE * 1000);
    offs.add(off);
    bins[Math.min(9, Math.floor((off / span) * 10))]++;
  }
  assert.ok(offs.size > 1900, 'offsets are not constant');
  for (const b of bins) assert.ok(b > 140 && b < 270, `bin count ${b} within +-35% of 200`);
  const e1 = await planDeposits({ nowMs: epochStartMs(E), trusts: ['same'], done: new Set(), seed: seed(5) });
  const e2 = await planDeposits({ nowMs: epochStartMs(E + 1), trusts: ['same'], done: new Set(), seed: seed(5) });
  assert.notEqual((e1.nextAtMs as number) - epochStartMs(E), (e2.nextAtMs as number) - epochStartMs(E + 1), 'the same trust moves between epochs');
});

test('P8 a different device seed gives a different schedule for the same trust (the seed is the only source of the jitter)', async () => {
  const a = await planDeposits({ nowMs: epochStartMs(E), trusts: ['x'], done: new Set(), seed: seed(6) });
  const b = await planDeposits({ nowMs: epochStartMs(E), trusts: ['x'], done: new Set(), seed: seed(7) });
  assert.notEqual(a.nextAtMs, b.nextAtMs);
});

test('P9 bad input is refused loudly: seed not 32 bytes, duplicate or empty trust ids, a non-finite clock', async () => {
  await assert.rejects(() => planDeposits({ nowMs: epochStartMs(E), trusts: ['a'], done: new Set(), seed: new Uint8Array(31) }), /seed/i);
  await assert.rejects(() => planDeposits({ nowMs: epochStartMs(E), trusts: ['a', 'a'], done: new Set(), seed: seed(1) }), /duplicate/i);
  await assert.rejects(() => planDeposits({ nowMs: epochStartMs(E), trusts: [''], done: new Set(), seed: seed(1) }), /trust id/i);
  await assert.rejects(() => planDeposits({ nowMs: Number.NaN, trusts: ['a'], done: new Set(), seed: seed(1) }), /clock/i);
});

test('P10 no trusts: nothing due, nothing scheduled', async () => {
  const p = await planDeposits({ nowMs: epochStartMs(E) + 5, trusts: [], done: new Set(), seed: seed(1) });
  assert.deepEqual(p, { due: [], nextAtMs: null });
});

test('P11 when every trust has deposited this epoch, the next planning moment is the START of the next epoch (not null, not never)', async () => {
  const done = new Set([depositKey('a', E), depositKey('b', E)]);
  const p = await planDeposits({ nowMs: epochStartMs(E) + 5_000_000, trusts: ['a', 'b'], done, seed: seed(9) });
  assert.deepEqual(p, { due: [], nextAtMs: epochStartMs(E + 1) });
});
