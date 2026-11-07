// The order of decisions for a sealed epoch note. Run: npx tsx --test src/lib/trust/psi-epoch-delivery.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { epochDeliveryOutcome, type EpochDeliveryInputs } from './psi-epoch-delivery';

async function run(over: Partial<{ receiveOn: boolean; inBook: boolean; blocked: boolean; macOk: boolean }>) {
  const calls: string[] = [];
  const v = { receiveOn: true, inBook: true, blocked: false, macOk: true, ...over };
  const inputs: EpochDeliveryInputs = {
    receiveOn: v.receiveOn,
    inBook: () => { calls.push('inBook'); return v.inBook; },
    blocked: () => { calls.push('blocked'); return v.blocked; },
    macOk: () => { calls.push('mac'); return v.macOk; },
  };
  return { outcome: await epochDeliveryOutcome(inputs), calls };
}

test('F1 off: benign ack, and NOTHING else is looked at (no lookup, no blocked check, no MAC)', async () => {
  for (const v of [{}, { inBook: false }, { blocked: true }, { macOk: false }]) {
    const r = await run({ ...v, receiveOn: false });
    assert.equal(r.outcome, 'benign-ack');
    assert.deepEqual(r.calls, []);
  }
});

test('only exactly true switches the path on', async () => {
  const r = await epochDeliveryOutcome({ receiveOn: 'true' as unknown as boolean, inBook: () => true, blocked: () => false, macOk: () => true });
  assert.equal(r, 'benign-ack');
});

test('a claimed sender not in the book is UNVERIFIED (never a not-in-book record), and neither blocked nor the MAC is consulted', async () => {
  const r = await run({ inBook: false });
  assert.equal(r.outcome, 'unverified');
  assert.deepEqual(r.calls, ['inBook']);
});

test('a blocked contact is dropped BEFORE the MAC: no pairwise secret is needed or exposed, even for a note that would verify', async () => {
  const r = await run({ blocked: true, macOk: true });
  assert.equal(r.outcome, 'blocked-drop');
  assert.deepEqual(r.calls, ['inBook', 'blocked']);
});

test('in the book, not blocked: a bad MAC is the no-fingerprint record, a good one is adopted', async () => {
  assert.equal((await run({ macOk: false })).outcome, 'bad-mac');
  assert.deepEqual((await run({ macOk: false })).calls, ['inBook', 'blocked', 'mac']);
  assert.equal((await run({ macOk: true })).outcome, 'adopt');
});

test('the thunks may be async: a lookup and a derivation that resolve later are awaited, in order', async () => {
  const order: string[] = [];
  const outcome = await epochDeliveryOutcome({
    receiveOn: true,
    inBook: async () => { await Promise.resolve(); order.push('inBook'); return true; },
    blocked: async () => { await Promise.resolve(); order.push('blocked'); return false; },
    macOk: async () => { await Promise.resolve(); order.push('mac'); return true; },
  });
  assert.equal(outcome, 'adopt');
  assert.deepEqual(order, ['inBook', 'blocked', 'mac']);
});

test('the five outcomes are exactly these (a new one is a deliberate edit)', async () => {
  const seen = new Set([
    (await run({ receiveOn: false })).outcome, (await run({ inBook: false })).outcome, (await run({ blocked: true })).outcome,
    (await run({ macOk: false })).outcome, (await run({})).outcome,
  ]);
  assert.deepEqual([...seen].sort(), ['adopt', 'bad-mac', 'benign-ack', 'blocked-drop', 'unverified']);
});

test('async answers that are FALSE (or true for blocked) are honoured, each step awaited: an unawaited promise would read as true', async () => {
  const later = <T,>(v: T) => async () => { await Promise.resolve(); return v; };
  const ok = { receiveOn: true, inBook: later(true), blocked: later(false), macOk: later(true) };
  assert.equal(await epochDeliveryOutcome({ ...ok, inBook: later(false) }), 'unverified');
  assert.equal(await epochDeliveryOutcome({ ...ok, blocked: later(true) }), 'blocked-drop');
  assert.equal(await epochDeliveryOutcome({ ...ok, macOk: later(false) }), 'bad-mac');
  assert.equal(await epochDeliveryOutcome(ok), 'adopt');
});

test('FAIL CLOSED: an answer that is not exactly the boolean takes the safe side, and later steps do not run', async () => {
  const calls: string[] = [];
  const mk = (v: { inBook?: unknown; blocked?: unknown; macOk?: unknown }): EpochDeliveryInputs => ({
    receiveOn: true,
    inBook: () => { calls.push('inBook'); return ('inBook' in v ? v.inBook : true) as boolean; },
    blocked: () => { calls.push('blocked'); return ('blocked' in v ? v.blocked : false) as boolean; },
    macOk: () => { calls.push('mac'); return ('macOk' in v ? v.macOk : true) as boolean; },
  });
  for (const bad of [undefined, null, 1, 'true', {}]) {
    calls.length = 0;
    assert.equal(await epochDeliveryOutcome(mk({ inBook: bad })), 'unverified', `inBook=${String(bad)}`);
    assert.deepEqual(calls, ['inBook']);
  }
  for (const bad of [undefined, null, 0, 'false', {}]) {
    calls.length = 0;
    assert.equal(await epochDeliveryOutcome(mk({ blocked: bad })), 'blocked-drop', `blocked=${String(bad)}`);
    assert.deepEqual(calls, ['inBook', 'blocked'], 'no secret is derived and no MAC is checked');
  }
  for (const bad of [undefined, null, 1, 'yes', {}]) {
    assert.equal(await epochDeliveryOutcome(mk({ macOk: bad })), 'bad-mac', `macOk=${String(bad)}`);
  }
});

test('a thunk that throws rejects the whole decision (the caller must retry, never treat it as benign)', async () => {
  const base: EpochDeliveryInputs = { receiveOn: true, inBook: () => true, blocked: () => false, macOk: () => true };
  await assert.rejects(epochDeliveryOutcome({ ...base, inBook: async () => { throw new Error('x'); } }));
  await assert.rejects(epochDeliveryOutcome({ ...base, blocked: () => { throw new Error('x'); } }));
  await assert.rejects(epochDeliveryOutcome({ ...base, macOk: async () => { throw new Error('x'); } }));
});
