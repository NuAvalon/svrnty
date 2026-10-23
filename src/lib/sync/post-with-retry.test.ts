// Unit tests for the bounded retry/backoff around the joiner-response POST (Peter #174621).
// Run: npx tsx --test src/lib/sync/post-with-retry.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { postWithRetry, isRetryableStatus } from './post-with-retry';

const noSleep = { sleep: async () => {}, random: () => 0.5 };
const seq = (...steps: Array<number | 'throw'>) => {
  const calls: any[] = [];
  const f = (async (_u: string, init: any) => {
    calls.push(init);
    const s = steps[Math.min(calls.length - 1, steps.length - 1)];
    if (s === 'throw') throw new Error('offline');
    return { ok: s >= 200 && s < 300, status: s };
  }) as unknown as typeof fetch;
  return { f, calls };
};

test('first-try 2xx: one POST, no sleep', async () => {
  const { f, calls } = seq(200);
  const sleeps: number[] = [];
  const r = await postWithRetry(f, '/x', { method: 'POST', body: 'b' }, { ...noSleep, sleep: async (m) => { sleeps.push(m); } });
  assert.deepEqual(r, { ok: true, status: 200, attempts: 1 });
  assert.equal(calls.length, 1);
  assert.deepEqual(sleeps, []);
});

test('503, 503, then 200: succeeds on try 3 with doubling backoff', async () => {
  const { f, calls } = seq(503, 503, 200);
  const sleeps: number[] = [];
  const r = await postWithRetry(f, '/x', { method: 'POST', body: 'same' }, { ...noSleep, sleep: async (m) => { sleeps.push(m); } });
  assert.deepEqual(r, { ok: true, status: 200, attempts: 3 });
  assert.deepEqual(sleeps, [500, 1000], 'random()=0.5 → ×1.0 jitter: 500 then 1000');
  assert.ok(calls.every((c) => c.body === 'same'), 'every attempt carries the identical body');
});

test('thrown fetch is retried, then reported as network-error after the cap', async () => {
  const { f, calls } = seq('throw');
  const r = await postWithRetry(f, '/x', {}, { ...noSleep, attempts: 3 });
  assert.deepEqual(r, { ok: false, status: 'network-error', attempts: 3 });
  assert.equal(calls.length, 3);
});

test('persistent 503: gives up after `attempts`, last status carried', async () => {
  const { f, calls } = seq(503);
  const r = await postWithRetry(f, '/x', {}, noSleep);
  assert.deepEqual(r, { ok: false, status: 503, attempts: 5 });
  assert.equal(calls.length, 5);
});

test('a non-retryable 4xx stops at once (400/403/413 — resending the same body cannot help)', async () => {
  for (const s of [400, 403, 413]) {
    const { f, calls } = seq(s);
    const r = await postWithRetry(f, '/x', {}, noSleep);
    assert.deepEqual(r, { ok: false, status: s, attempts: 1 });
    assert.equal(calls.length, 1);
  }
});

test('429 and 408 ARE retried', async () => {
  for (const s of [429, 408]) {
    const { f } = seq(s, 200);
    const r = await postWithRetry(f, '/x', {}, noSleep);
    assert.deepEqual(r, { ok: true, status: 200, attempts: 2 });
  }
  assert.equal(isRetryableStatus(404), false);
  assert.equal(isRetryableStatus(599), true);
});

test('backoff is capped at maxDelayMs', async () => {
  const { f } = seq(503);
  const sleeps: number[] = [];
  await postWithRetry(f, '/x', {}, { ...noSleep, attempts: 6, baseDelayMs: 4000, maxDelayMs: 8000, sleep: async (m) => { sleeps.push(m); } });
  assert.deepEqual(sleeps, [4000, 8000, 8000, 8000, 8000]);
});

test('a hung request is aborted by the per-attempt timeout and retried', async () => {
  let n = 0;
  const f = ((_u: string, init: any) => {
    n++;
    if (n === 1) return new Promise((_res, rej) => init.signal.addEventListener('abort', () => rej(new Error('aborted'))));
    return Promise.resolve({ ok: true, status: 200 });
  }) as unknown as typeof fetch;
  const r = await postWithRetry(f, '/x', {}, { ...noSleep, timeoutMs: 30 });
  assert.deepEqual(r, { ok: true, status: 200, attempts: 2 });
});
