// src/lib/lenses/lens-display.test.ts — review-1 item 5: lens values show as GIVEN, and a value
// differing from the signed-path one shows as CHANGED — for any method kind.
// Run: npx tsx --test src/lib/lenses/lens-display.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { heldValuesForKind, lensDisplayRows } from './lens-display';
import { lensChangedLine, lensChangedWasLine, lensGivenLine, lensSharedSlotLine, lensStoppedLine, lensTooLargeLine, EXTRA_METHODS_LENS_LINE, EXTRA_METHODS_LOCAL_LINE } from './lens-copy';
import { lensMethodKey } from './lens-wire';

const contact = (over: Record<string, unknown> = {}) => ({
  email: 'signed@x.example',
  phones: ['+111'],
  contact_info: {
    emails: ['signed@x.example'],
    phones: ['+111'],
    urls: ['https://signed.example'],
    handles: { signal: '@signed' },
  },
  ...over,
});

test('item 5: a lens value differing from the held signed value is marked CHANGED with the old value', () => {
  const c = contact({
    contact_info: {
      ...contact().contact_info,
      lens_methods: {
        [lensMethodKey({ kind: 'signal' })]: { kind: 'signal', value: '@swapped' },
        [lensMethodKey({ kind: 'phone' })]: { kind: 'phone', value: '+999' },
        [lensMethodKey({ kind: 'email' })]: { kind: 'email', value: 'signed@x.example' },
        [lensMethodKey({ kind: 'custom', label: 'pgp' })]: { kind: 'custom', value: 'ABCD', label: 'pgp' },
      },
    },
  });
  const rows = lensDisplayRows(c);
  const byKey = new Map(rows.map((r) => [r.key, r]));
  assert.equal(byKey.get(lensMethodKey({ kind: 'signal' }))!.heldValue, '@signed', 'handle differs ⇒ changed');
  assert.equal(byKey.get(lensMethodKey({ kind: 'phone' }))!.heldValue, '+111', 'phone differs ⇒ changed');
  assert.equal(byKey.get(lensMethodKey({ kind: 'email' }))!.heldValue, null, 'same value ⇒ just given');
  assert.equal(byKey.get(lensMethodKey({ kind: 'custom', label: 'pgp' }))!.heldValue, null, 'no signed home ⇒ can only be given');
});

test('heldValuesForKind: url kinds share the signed urls list; unknown kinds hold nothing', () => {
  const c = contact();
  assert.deepEqual(heldValuesForKind(c, 'site'), ['https://signed.example']);
  assert.deepEqual(heldValuesForKind(c, 'url'), ['https://signed.example']);
  assert.deepEqual(heldValuesForKind(c, 'custom'), []);
  assert.deepEqual(heldValuesForKind({}, 'email'), []);
});

test('item 5/11: the exact contract strings', () => {
  assert.equal(lensGivenLine('Ana'), 'Ana gave you this.');
  assert.equal(
    lensChangedLine('Ana', 'Phone'),
    "Ana's Phone changed. Before you rely on the new one, check with them some other way, not through the new one.",
  );
  assert.equal(lensChangedWasLine('+111'), 'Was: +111');
  assert.equal(EXTRA_METHODS_LENS_LINE, 'Extra methods go only to the people whose lens includes them.');
  assert.equal(EXTRA_METHODS_LOCAL_LINE, 'Extra methods stay on this device until the living card schema carries them.');
});

test('a malformed lens_methods map yields no rows (never throws on hostile record data)', () => {
  const c = contact({ contact_info: { lens_methods: { bad: { nope: 1 }, also: null } } });
  assert.equal(lensDisplayRows(c).length, 0);
  assert.equal(lensDisplayRows({ contact_info: 'junk' }).length, 0);
});

test('R6a display: a stored "was" marks the row CHANGED; kindChanged names the kind', () => {
  const c = contact({
    contact_info: {
      lens_methods: {
        [lensMethodKey({ kind: 'custom', label: 'pgp' })]: { kind: 'custom', value: 'B', label: 'pgp', was: 'A' },
        [lensMethodKey({ kind: 'phone', label: 'Mobile' })]: { kind: 'phone', value: '+222', label: 'Mobile', was: '+111', wasKind: true },
      },
    },
  });
  const rows = lensDisplayRows(c);
  const byKey = new Map(rows.map((r) => [r.key, r]));
  assert.equal(byKey.get(lensMethodKey({ kind: 'custom', label: 'pgp' }))!.heldValue, 'A');
  const swap = byKey.get(lensMethodKey({ kind: 'phone', label: 'Mobile' }))!;
  assert.equal(swap.heldValue, '+111');
  assert.equal(swap.kindChanged, true);
});

test('R6b display: a LABELLED lens value beside an unchanged signed value shows as GIVEN', () => {
  const c = contact({
    contact_info: {
      ...contact().contact_info,
      lens_methods: {
        [lensMethodKey({ kind: 'phone', label: 'Work' })]: { kind: 'phone', value: '+999', label: 'Work' },
      },
    },
  });
  const rows = lensDisplayRows(c);
  assert.equal(rows[0].heldValue, null, 'a new slot shows as given — the signed home phone is another slot');
});

test('D1/D2/R8a copy: no-name changed form, per-recipient too-large, stopped, shared-slot ask', () => {
  assert.equal(lensChangedLine('', 'Email'), "Their Email changed. Before you rely on the new one, check with them some other way, not through the new one.");
  assert.equal(lensTooLargeLine('Ana'), 'This lens has too much in it to send to Ana. Nothing went to them.');
  assert.equal(lensStoppedLine('Ana'), "Updates from Ana can't be shown here any more. Ask them for their current card.");
  assert.equal(lensSharedSlotLine('phone'), 'Two phone numbers in this lens have the same label. Give each one its own label before you send it.');
  assert.equal(lensSharedSlotLine('email'), 'Two email addresses in this lens have the same label. Give each one its own label before you send it.');
});
