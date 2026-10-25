// Run: npx tsx --test src/lib/notes/thread-load-guard.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createThreadLoadGuard } from './thread-load-guard';

// Simulates the selection effect: it re-runs once per `threads` identity change (i.e. once per reload / arrival) and
// loads only when shouldLoad() says so. The e2e cannot pin this (the 1.5 s periodic tick refreshes the thread anyway),
// so the load COUNT is asserted here.
function effectRuns(guard: ReturnType<typeof createThreadLoadGuard>, threadIds: Array<string | null>): number {
  let loads = 0;
  for (const id of threadIds) if (guard.shouldLoad(id)) loads++;
  return loads;
}

test('60 arrivals into the SAME thread (a new threads array each time) → exactly 1 load, not 60', () => {
  const g = createThreadLoadGuard();
  assert.equal(effectRuns(g, Array(60).fill('thr_a')), 1);
});

test('first arrival creating the thread (null → id) still loads, then no re-fire', () => {
  const g = createThreadLoadGuard();
  assert.equal(effectRuns(g, [null, null, 'thr_a', 'thr_a', 'thr_a']), 2); // initial null + the id appearing
});

test('switching threads A → B → A loads each time (the nextId-change case must not be suppressed)', () => {
  const g = createThreadLoadGuard();
  assert.equal(effectRuns(g, ['thr_a', 'thr_a', 'thr_b', 'thr_b', 'thr_a']), 3);
});

test('nothing selected / no thread (null, null, …) → one load only', () => {
  const g = createThreadLoadGuard();
  assert.equal(effectRuns(g, [null, null, null]), 1);
});
