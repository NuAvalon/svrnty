// src/lib/lenses/lens-plan.test.ts — contract R3 (widening confirmed per recipient; no bulk bypass).
// Run: npx tsx --test src/lib/lenses/lens-plan.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { OwnerCardBag } from '../../components/identity/owner-card';
import { planLensReassign, plansNeedingConfirm } from './lens-plan';
import type { LensGrantBook } from './lens-grants';
import { LENS_EXPLAINER, lensNarrowingNote, lensWideningWarning } from './lens-copy';

const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

const bag: OwnerCardBag = {
  methods: [
    { id: 'm-email', kind: 'email', value: 'me@work.example' },
    { id: 'm-signal', kind: 'signal', value: '@me' },
  ],
  lenses: [
    { id: 'lens-min', name: 'Minimal', methodIds: [] },
    { id: 'lens-some', name: 'Some', methodIds: ['m-email'] },
    { id: 'lens-all', name: 'All', methodIds: ['m-email', 'm-signal'] },
  ],
  defaultLensId: 'lens-some',
};

const book = (grants: LensGrantBook['grants']): LensGrantBook => ({ v: 1, grants });

test('R3: moving to a face that exposes a new method is a WIDENING — per-recipient confirm required', () => {
  // A holds lens-some; reassignment to lens-all adds 'signal' → widening.
  const plan = planLensReassign(bag, book({ [FP_A]: { lens: 'lens-some' } }), FP_A, 'lens-all');
  assert.equal(plan.widening, true);
  assert.deepEqual(plan.added, [{ kind: 'signal', value: '@me' }]);
  assert.deepEqual(plan.removed, []);
  // B holds nothing → the narrowest face (lens-min, 0 methods); to lens-some adds email → widening too.
  const planB = planLensReassign(bag, book({}), FP_B, 'lens-some');
  assert.equal(planB.widening, true);
  assert.deepEqual(planB.added, [{ kind: 'email', value: 'me@work.example' }]);
});

test('R3: narrowing and same-face moves need NO confirm — plansNeedingConfirm splits them per recipient', () => {
  const narrow = planLensReassign(bag, book({ [FP_A]: { lens: 'lens-all' } }), FP_A, 'lens-min');
  assert.equal(narrow.widening, false);
  assert.deepEqual(narrow.removed, [
    { kind: 'email', value: 'me@work.example' },
    { kind: 'signal', value: '@me' },
  ]);
  const same = planLensReassign(bag, book({ [FP_A]: { lens: 'lens-some' } }), FP_A, 'lens-some');
  assert.equal(same.widening, false);
  const widen = planLensReassign(bag, book({ [FP_B]: { lens: 'lens-min' } }), FP_B, 'lens-all');
  // A batch: only the widening plan requires a per-recipient confirm — narrowing ships without one.
  const needing = plansNeedingConfirm([narrow, same, widen]);
  assert.deepEqual(needing.map((p) => p.fingerprint), [FP_B]);
});

test('R6: the exact contract strings are what the view renders', () => {
  assert.equal(
    lensWideningWarning('Ada', 'Signal'),
    "This gives Ada your Signal. Once it's sent, you can't take it back.",
  );
  assert.equal(
    lensNarrowingNote('Ada'),
    "Ada won't get updates to this any more. They keep what they already have.",
  );
  assert.equal(LENS_EXPLAINER, 'Anyone you give a card to can pass it on.');
});
