// Run: npx tsx --test src/components/relay/relay-holds-refresh.test.ts
// The refresh button's own minimum gap. The panel never makes a request just by being opened; the button asks the revoke check to read the relay again, and not more often than this.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { REFRESH_MIN_GAP_MS, canRefresh } from './relay-holds-refresh';
import { DRAIN_MIN_GAP_MS } from '@/lib/sync/allowed-revoke';

test('RHG1 the button\'s gap is ABOVE the revoke check\'s own spacing, so a press can never be what the relay\'s rate bucket sees first', () => {
  assert.ok(REFRESH_MIN_GAP_MS > DRAIN_MIN_GAP_MS, `${REFRESH_MIN_GAP_MS} must exceed ${DRAIN_MIN_GAP_MS}`);
  assert.equal(REFRESH_MIN_GAP_MS, 10_000);
});

test('RHG2 the first press is allowed; a press AT the gap is allowed and ONE ms before it is not, with the wait that is left', () => {
  assert.deepEqual(canRefresh(undefined, 5_000), { allowed: true, waitMs: 0 });
  assert.deepEqual(canRefresh(1_000, 1_000 + REFRESH_MIN_GAP_MS), { allowed: true, waitMs: 0 });
  assert.deepEqual(canRefresh(1_000, 1_000 + REFRESH_MIN_GAP_MS - 1), { allowed: false, waitMs: 1 });
  assert.deepEqual(canRefresh(1_000, 1_000), { allowed: false, waitMs: REFRESH_MIN_GAP_MS }, 'a press the instant after one waits the whole gap');
});

test('RHG3 a clock that moved BACK (or a bad stored time) never freezes the button: it is allowed, and the revoke check\'s own spacing still protects the relay', () => {
  assert.deepEqual(canRefresh(50_000, 10_000), { allowed: true, waitMs: 0 });
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) assert.deepEqual(canRefresh(bad, 10_000), { allowed: true, waitMs: 0 }, String(bad));
});
