// contact-events tests — the live-beat reactivity primitive + its honesty guarantees.
// Run: npx tsx --test
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  emitContactChange,
  subscribeContactChanges,
  __resetContactEventsForTest,
  type ContactChangeEvent,
} from './contact-events';

after(() => __resetContactEventsForTest()); // close the channel so the test process exits cleanly

test('local emit fans out to subscribers as source=local', () => {
  __resetContactEventsForTest();
  const got: ContactChangeEvent[] = [];
  const off = subscribeContactChanges((e) => got.push(e));
  emitContactChange({ ids: ['c1'], reason: 'ui-edit' });
  off();
  assert.equal(got.length, 1);
  assert.deepEqual(got[0].ids, ['c1']);
  assert.equal(got[0].reason, 'ui-edit');
  assert.equal(got[0].source, 'local'); // this page's own write, not a live-push
});

test('unsubscribe stops delivery', () => {
  __resetContactEventsForTest();
  let n = 0;
  const off = subscribeContactChanges(() => { n++; });
  emitContactChange({ ids: ['a'], reason: 'ui-edit' });
  off();
  emitContactChange({ ids: ['b'], reason: 'ui-edit' });
  assert.equal(n, 1); // only the pre-unsubscribe emit
});

test('reason is carried verbatim (live-apply is the last_interaction-reset path)', () => {
  __resetContactEventsForTest();
  const seen: string[] = [];
  const off = subscribeContactChanges((e) => seen.push(e.reason));
  for (const r of ['ui-edit', 'import', 'live-apply', 'delete'] as const) emitContactChange({ ids: ['x'], reason: r });
  off();
  assert.deepEqual(seen, ['ui-edit', 'import', 'live-apply', 'delete']);
});

test('a throwing subscriber does not break fan-out to the others', () => {
  __resetContactEventsForTest();
  let reached = false;
  const off1 = subscribeContactChanges(() => { throw new Error('bad subscriber'); });
  const off2 = subscribeContactChanges(() => { reached = true; });
  emitContactChange({ ids: ['x'], reason: 'ui-edit' });
  off1(); off2();
  assert.equal(reached, true);
});

test('HONESTY: a cross-context push arrives as source=broadcast (the true live-push signal)', async () => {
  __resetContactEventsForTest();
  const got: ContactChangeEvent[] = [];
  // Resolve as soon as the cross-context push ARRIVES — robust vs event-loop load when the full suite
  // shares one process (a fixed 30ms timeout flaked there, passing alone); cap at 1s so a miss can't hang.
  const arrived = new Promise<void>((resolve) => {
    subscribeContactChanges((e) => { got.push(e); if (e.source === 'broadcast') resolve(); });
  });
  const peer = new BroadcastChannel('svrnty:contacts'); // simulate ANOTHER tab/context
  peer.postMessage({ ids: ['c9'], reason: 'live-apply' });
  await Promise.race([arrived, new Promise<void>((r) => setTimeout(r, 1000))]);
  peer.close();
  const broadcasts = got.filter((e) => e.source === 'broadcast');
  assert.equal(broadcasts.length, 1, 'cross-context push should arrive exactly once as broadcast');
  assert.equal(broadcasts[0].source, 'broadcast'); // NOT 'local' — this is the honest live signal
  assert.deepEqual(broadcasts[0].ids, ['c9']);
  assert.equal(broadcasts[0].reason, 'live-apply');
});

test('HONESTY: a local emit does NOT echo back to its own emitter as broadcast (live signal cannot be faked locally)', async () => {
  __resetContactEventsForTest();
  const got: ContactChangeEvent[] = [];
  const off = subscribeContactChanges((e) => got.push(e));
  emitContactChange({ ids: ['self'], reason: 'ui-edit' });
  await new Promise((r) => setTimeout(r, 30)); // give any (incorrect) self-echo time to arrive
  off();
  assert.equal(got.length, 1); // exactly the one local fan-out
  assert.equal(got[0].source, 'local');
  assert.equal(got.filter((e) => e.source === 'broadcast').length, 0); // no self-echo → beat-4 can't false-claim "live"
});
