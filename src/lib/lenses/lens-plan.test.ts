// src/lib/lenses/lens-plan.test.ts — contract R3 (per-recipient widening confirm) on the SENT-SET
// baseline (review-1 items 1+3): a plan from no record treats every method it would send as a
// widening; a method added to a held lens does not launder through a reassign.
// Run: npx tsx --test src/lib/lenses/lens-plan.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { OwnerCardBag } from '../../components/identity/owner-card';
import { commitReassignPlan, planLensReassign, plansNeedingConfirm } from './lens-plan';
import { lensSentKeys, recordLensKeys, setRecipientLens, type LensGrantBook } from './lens-grants';
import { lensWideningWarning, lensNarrowingNote, LENS_EXPLAINER } from './lens-copy';

const FP = 'b'.repeat(64);

const bag: OwnerCardBag = {
  methods: [
    { id: 'm-email', kind: 'email', value: 'me@work.example' },
    { id: 'm-signal', kind: 'signal', value: '@me' },
    { id: 'm-insta', kind: 'instagram', value: '@me.off' },
  ],
  lenses: [
    { id: 'lens-everyone', name: 'Everyone', methodIds: ['m-email'] },
    { id: 'lens-close', name: 'Close', methodIds: ['m-email', 'm-signal', 'm-insta'] },
  ],
  defaultLensId: 'lens-everyone',
};

const bookWith = (grants: LensGrantBook['grants']): LensGrantBook => ({ v: 1, grants });
const emailKey = 'm-email';
const signalKey = 'm-signal';

test('item 1: a Revise plan from NO RECORD treats every method it would send as a widening', () => {
  const book = bookWith({}); // no record at all — zero methods are theirs
  const plan = planLensReassign(bag, book, FP, 'lens-close');
  assert.equal(plan.widening, true);
  assert.equal(plan.added.length, 3, 'all of lens-close is a widening: nothing was ever sent');
  assert.equal(plan.removed.length, 0);
  assert.ok(plansNeedingConfirm([plan]).length === 1);
});

test('R3: moving to a face that exposes a NEW (unsent) method is a WIDENING — confirm per recipient', () => {
  const book = recordLensKeys(setRecipientLens(bookWith({}), FP, 'lens-everyone'), FP, [emailKey]);
  const plan = planLensReassign(bag, book, FP, 'lens-close');
  assert.equal(plan.widening, true);
  assert.deepEqual(plan.added.map((m) => m.kind).sort(), ['instagram', 'signal']);
  // Same-face and pure-narrowing moves need no confirm.
  const narrow = planLensReassign(bag, book, FP, 'lens-everyone');
  assert.equal(narrow.widening, false);
});

test('item 3: a method added to the lens but NOT yet confirmed is still a widening through a reassign', () => {
  // The lens was edited to add signal; the confirm never landed (sent has only email). Moving to a
  // different lens that also carries signal must NOT treat signal as already given.
  const edited: OwnerCardBag = {
    ...bag,
    lenses: bag.lenses.map((l) => (l.id === 'lens-everyone' ? { ...l, methodIds: ['m-email', 'm-signal'] } : l)),
  };
  const book = recordLensKeys(setRecipientLens(bookWith({}), FP, 'lens-everyone'), FP, [emailKey]);
  const plan = planLensReassign(edited, book, FP, 'lens-close');
  assert.equal(plan.widening, true);
  assert.ok(plan.added.some((m) => m.kind === 'signal'), 'the unconfirmed key widens again — no laundering');
  // And 'removed' counts only what actually flows (email), not the pending key.
  const back = planLensReassign(edited, book, FP, null);
  assert.deepEqual(back.removed.map((m) => m.kind), ['email']);
});

test('commitReassignPlan: assigns the lens AND records the confirmed widening keys', () => {
  const book = bookWith({ [FP]: { capable: true } });
  const plan = planLensReassign(bag, book, FP, 'lens-close');
  const next = commitReassignPlan(book, plan);
  assert.equal(next.grants[FP]!.lens, 'lens-close');
  assert.ok(lensSentKeys(next, FP).has(emailKey) && lensSentKeys(next, FP).has(signalKey), 'confirmed keys enter the sent set');
});

test('R6: the exact contract strings are what the view renders', () => {
  assert.equal(lensWideningWarning('Ana', 'Signal'), "This gives Ana your Signal. Once it's sent, you can't take it back.");
  assert.equal(lensNarrowingNote('Ana'), "Ana won't get updates to this any more. They keep what they already have.");
  assert.equal(LENS_EXPLAINER, 'Anyone you give a card to can pass it on.');
});

test('item 9: lens-plan.ts holds NO NUL byte — git must diff it as text (review visibility)', () => {
  const dir = fileURLToPath(new URL('.', import.meta.url));
  const raw = readFileSync(`${dir}/lens-plan.ts`);
  assert.equal(raw.includes(0), false, 'a literal NUL makes git treat the file as binary');
  const src = raw.toString('utf8');
  assert.equal(/lensMethodKey\s*\(/.test(src.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '')), false,
    'R3a: the plan keys on the owner method id — a wire-slot key must never come back');
});

test('R3a: moving between two lenses whose methods share a SLOT is a widening (method-id keying)', () => {
  const two: OwnerCardBag = {
    methods: [
      { id: 'm-phone-work', kind: 'phone', value: '+15550001' },
      { id: 'm-phone-personal', kind: 'phone', value: '+19990002' },
    ],
    lenses: [
      { id: 'lens-work', name: 'Work', methodIds: ['m-phone-work'] },
      { id: 'lens-personal', name: 'Personal', methodIds: ['m-phone-personal'] },
    ],
  };
  const book = recordLensKeys(setRecipientLens(bookWith({}), FP, 'lens-work'), FP, ['m-phone-work']);
  const plan = planLensReassign(two, book, FP, 'lens-personal');
  assert.equal(plan.widening, true, 'same slot (unlabelled phone), different method — the confirm is required');
  assert.deepEqual(plan.added.map((m) => m.id), ['m-phone-personal']);
  assert.equal(plansNeedingConfirm([plan]).length, 1);
});
