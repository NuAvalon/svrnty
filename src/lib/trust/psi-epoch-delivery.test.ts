// The order of decisions for a sealed epoch note. Run: npx tsx --test src/lib/trust/psi-epoch-delivery.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { epochDeliveryOutcome, type EpochDeliveryInputs } from './psi-epoch-delivery';

function run(over: Partial<{ receiveOn: boolean; inBook: boolean; blocked: boolean; macOk: boolean }>) {
  const calls: string[] = [];
  const v = { receiveOn: true, inBook: true, blocked: false, macOk: true, ...over };
  const inputs: EpochDeliveryInputs = {
    receiveOn: v.receiveOn,
    inBook: () => { calls.push('inBook'); return v.inBook; },
    blocked: () => { calls.push('blocked'); return v.blocked; },
    macOk: () => { calls.push('mac'); return v.macOk; },
  };
  return { outcome: epochDeliveryOutcome(inputs), calls };
}

test('F1 off: benign ack, and NOTHING else is looked at (no lookup, no blocked check, no MAC)', () => {
  for (const v of [{}, { inBook: false }, { blocked: true }, { macOk: false }]) {
    const r = run({ ...v, receiveOn: false });
    assert.equal(r.outcome, 'benign-ack');
    assert.deepEqual(r.calls, []);
  }
});

test('only exactly true switches the path on', () => {
  const r = epochDeliveryOutcome({ receiveOn: 'true' as unknown as boolean, inBook: () => true, blocked: () => false, macOk: () => true });
  assert.equal(r, 'benign-ack');
});

test('a claimed sender not in the book is UNVERIFIED (never a not-in-book record), and neither blocked nor the MAC is consulted', () => {
  const r = run({ inBook: false });
  assert.equal(r.outcome, 'unverified');
  assert.deepEqual(r.calls, ['inBook']);
});

test('a blocked contact is dropped BEFORE the MAC: no pairwise secret is needed or exposed, even for a note that would verify', () => {
  const r = run({ blocked: true, macOk: true });
  assert.equal(r.outcome, 'blocked-drop');
  assert.deepEqual(r.calls, ['inBook', 'blocked']);
});

test('in the book, not blocked: a bad MAC is the no-fingerprint record, a good one is adopted', () => {
  assert.equal(run({ macOk: false }).outcome, 'bad-mac');
  assert.deepEqual(run({ macOk: false }).calls, ['inBook', 'blocked', 'mac']);
  assert.equal(run({ macOk: true }).outcome, 'adopt');
});

test('the five outcomes are exactly these (a new one is a deliberate edit)', () => {
  const seen = new Set([
    run({ receiveOn: false }).outcome, run({ inBook: false }).outcome, run({ blocked: true }).outcome, run({ macOk: false }).outcome, run({}).outcome,
  ]);
  assert.deepEqual([...seen].sort(), ['adopt', 'bad-mac', 'benign-ack', 'blocked-drop', 'unverified']);
});
