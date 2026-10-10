import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  addOwnerLens,
  addOwnerMethod,
  emptyOwnerCard,
  lensForGroupName,
  methodsForLens,
  preferredMethod,
  setLensPreferred,
  toggleLensMethod,
} from './owner-card';

test('new methods join the default lens; preferred can be starred', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'email', 'work@corp.test');
  bag = addOwnerMethod(bag, 'instagram', '@festival.me');
  const everyone = bag.lenses[0];
  assert.equal(everyone.methodIds.length, 2);
  bag = setLensPreferred(bag, everyone.id, bag.methods[1].id);
  assert.equal(preferredMethod(bag)?.kind, 'instagram');
});

test('a named lens is a subset — not the whole card', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'email', 'work@corp.test');
  bag = addOwnerMethod(bag, 'instagram', '@festival.me');
  bag = addOwnerLens(bag, 'Business');
  const biz = bag.lenses.find((l) => l.name === 'Business')!;
  bag = toggleLensMethod(bag, biz.id, bag.methods[0].id);
  const shown = methodsForLens(bag, biz.id);
  assert.equal(shown.length, 1);
  assert.equal(shown[0].kind, 'email');
});

test('lensForGroupName matches an owner-named group, else default', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerLens(bag, 'Festival');
  const fest = bag.lenses.find((l) => l.name === 'Festival')!;
  assert.equal(lensForGroupName(bag, 'festival')?.id, fest.id);
  assert.equal(lensForGroupName(bag, 'unknown')?.id, bag.defaultLensId);
});
