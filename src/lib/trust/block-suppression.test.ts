// src/lib/trust/block-suppression.test.ts
// ADVERSARIAL gate for the piece-2 block→suppression-record POPULATE write-path (task #579, Archie do-no-harm
// gate #159479/#159668). Refutes survivor-safety properties, not "a value round-trips":
//   · §F3 FAIL-CLOSED: an UNREADABLE record (null) is NEVER overwritten — setSuppressionRecord is not called,
//     so a corrupt record's suppress-all can never be reduced to suppress-one (the survivor RE-EXPOSE),
//   · block ADDS the peer's canonical durable_id; unblock REMOVES exactly it; both idempotent,
//   · a keyless/gray contact (no fingerprint) is a no-op (nothing durable to suppress),
//   · block touches ONLY persons — global / groups / other persons are preserved (no collateral change),
//   · durable_id keying is case-insensitive / trimmed (rotation-stable canonical fp, not UUID/mailbox/route),
//   · a write failure NEVER throws to the caller (the block still holds via the record + the `blocked` flag).
// Run: npx tsx --test src/lib/trust/block-suppression.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyBlockSuppression, type SuppressionStoreSeam } from '@/lib/trust/block-suppression';
import { emptySuppression, type SuppressionRecord } from '@/lib/trust/suppression';

const OWNER = 'f'.repeat(64);
const PEER = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);

/** In-memory store seam + a setCalls counter so we can assert the fail-closed path NEVER writes. */
function makeStore(initial: SuppressionRecord | null): {
  store: SuppressionStoreSeam;
  setCalls: () => number;
  current: () => SuppressionRecord | null;
  setThrows: (on: boolean) => void;
} {
  let rec = initial;
  let calls = 0;
  let throwOnSet = false;
  return {
    store: {
      getSuppressionRecord: async () => rec,
      setSuppressionRecord: async (_owner, next) => {
        calls += 1;
        if (throwOnSet) throw new Error('session locked (simulated)');
        rec = next;
      },
    },
    setCalls: () => calls,
    current: () => rec,
    setThrows: (on: boolean) => {
      throwOnSet = on;
    },
  };
}

test('block ADDS the peer durable_id to the record', async () => {
  const m = makeStore(emptySuppression());
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, true);
  assert.equal(r.outcome, 'added');
  assert.deepEqual(m.current()?.persons, [PEER]);
  assert.equal(m.setCalls(), 1);
});

test('block is IDEMPOTENT — re-blocking an already-suppressed person does not re-write', async () => {
  const m = makeStore({ global: false, groups: [], persons: [PEER] });
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'already');
  assert.equal(m.setCalls(), 0); // no redundant write
  assert.deepEqual(m.current()?.persons, [PEER]);
});

test('unblock REMOVES exactly the peer durable_id', async () => {
  const m = makeStore({ global: false, groups: [], persons: [PEER, OTHER] });
  const r = await applyBlockSuppression(OWNER, PEER, false, m.store);
  assert.equal(r.wrote, true);
  assert.equal(r.outcome, 'removed');
  assert.deepEqual(m.current()?.persons, [OTHER]); // only PEER removed
  assert.equal(m.setCalls(), 1);
});

test('unblock of a NON-suppressed person is a no-op (no redundant write)', async () => {
  const m = makeStore({ global: false, groups: [], persons: [OTHER] });
  const r = await applyBlockSuppression(OWNER, PEER, false, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'already');
  assert.equal(m.setCalls(), 0);
  assert.deepEqual(m.current()?.persons, [OTHER]);
});

test('★ §F3 FAIL-CLOSED: an UNREADABLE record (null) is NEVER overwritten — no reduce-to-suppress-one', async () => {
  const m = makeStore(null); // locked / decrypt-fail / malformed / absent
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'skipped-fail-closed');
  assert.equal(m.setCalls(), 0); // THE survivor-safety assertion: we never write over an unreadable record
  assert.equal(m.current(), null);
});

test('§F3 fail-closed also holds for UNBLOCK on a null record (never materializes a reduced record)', async () => {
  const m = makeStore(null);
  const r = await applyBlockSuppression(OWNER, PEER, false, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'skipped-fail-closed');
  assert.equal(m.setCalls(), 0);
});

test('keyless/gray contact (no fingerprint) is a no-op — no store access at all', async () => {
  const keyless: Array<string | undefined | null> = ['', '   ', undefined, null];
  for (const bad of keyless) {
    const m = makeStore(emptySuppression());
    const r = await applyBlockSuppression(OWNER, bad, true, m.store);
    assert.equal(r.wrote, false);
    assert.equal(r.outcome, 'no-durable-id');
    assert.equal(m.setCalls(), 0);
  }
});

test('block touches ONLY persons — global + groups + other persons preserved', async () => {
  const m = makeStore({ global: true, groups: ['g1', 'g2'], persons: [OTHER] });
  await applyBlockSuppression(OWNER, PEER, true, m.store);
  const rec = m.current()!;
  assert.equal(rec.global, true);
  assert.deepEqual(rec.groups, ['g1', 'g2']);
  assert.deepEqual(rec.persons.sort(), [OTHER, PEER].sort());
});

test('durable_id keying is case-insensitive + trimmed (canonical fp, not a raw UUID)', async () => {
  const m = makeStore(emptySuppression());
  await applyBlockSuppression(OWNER, `  ${PEER.toUpperCase()}  `, true, m.store);
  assert.deepEqual(m.current()?.persons, [PEER]); // normalized to lowercase + trimmed
  // re-block the lowercase form → idempotent (same canonical id)
  const r2 = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r2.outcome, 'already');
  assert.equal(m.setCalls(), 1); // only the first write happened
});

test('a write failure NEVER throws to the caller (block still holds via record + blocked flag)', async () => {
  const m = makeStore(emptySuppression());
  m.setThrows(true);
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'skipped-error'); // swallowed, not thrown
});
