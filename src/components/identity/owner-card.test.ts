import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  addOwnerLens,
  addOwnerMethod,
  cardMethodsForFace,
  emptyOwnerCard,
  lensForGroupName,
  methodsForLens,
  ownerLensFace,
  patchLensProfile,
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

test('each lens has its own profile face — name and methods differ', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'email', 'work@corp.test');
  bag = addOwnerMethod(bag, 'instagram', '@festival.me');
  bag = addOwnerLens(bag, 'Festival');
  const fest = bag.lenses.find((l) => l.name === 'Festival')!;
  bag = toggleLensMethod(bag, fest.id, bag.methods[1].id);
  bag = patchLensProfile(bag, fest.id, {
    displayName: 'Archie',
    handle: 'archie.fest',
    note: 'festival face',
  });

  const everyone = ownerLensFace(bag, bag.defaultLensId, { displayName: 'Peter', handle: 'peter.svrnty.is' });
  const festival = ownerLensFace(bag, fest.id, { displayName: 'Peter', handle: 'peter.svrnty.is' });

  assert.equal(everyone.displayName, 'Peter');
  assert.equal(everyone.handle, 'peter.svrnty.is');
  assert.equal(everyone.isDefault, true);
  assert.equal(festival.displayName, 'Archie');
  assert.equal(festival.handle, 'archie.fest');
  assert.equal(festival.note, 'festival face');
  assert.equal(festival.isDefault, false);

  const everyoneRows = cardMethodsForFace(bag, everyone, { email: 'work@corp.test' });
  const festivalRows = cardMethodsForFace(bag, festival);
  assert.ok(everyoneRows.some((m) => m.kind === 'email'));
  assert.ok(everyoneRows.some((m) => m.kind === 'signal'));
  assert.equal(festivalRows.length, 1);
  assert.equal(festivalRows[0].kind, 'instagram');
  assert.ok(!festivalRows.some((m) => m.kind === 'email'));
});
