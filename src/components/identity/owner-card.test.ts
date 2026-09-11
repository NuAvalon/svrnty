import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  addOwnerLens,
  addOwnerMethod,
  emptyOwnerCard,
  hydrateOwnerCard,
  lensForGroupName,
  methodRelayHost,
  methodsForLens,
  ownerCardBytes,
  ownerCardHasInlinedBinary,
  OWNER_CARD_SOFT_CAP_BYTES,
  preferredMethod,
  saveOwnerCard,
  setDefaultLens,
  setLensPreferred,
  toggleLensMethod,
  updateOwnerMethod,
} from './owner-card';

function memStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => {
      map.set(k, v);
    },
    removeItem: (k: string) => {
      map.delete(k);
    },
    clear: () => map.clear(),
  };
}

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

test('typed custom field persists label + valueType', () => {
  (globalThis as { localStorage?: ReturnType<typeof memStorage> }).localStorage = memStorage();
  const fp = 'aa'.repeat(20);
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'custom', 'blue', 'Favorite color', { valueType: 'text' });
  const saved = saveOwnerCard(fp, bag);
  assert.equal(saved.ok, true);
  const loaded = hydrateOwnerCard(fp);
  const custom = loaded.methods.find((m) => m.kind === 'custom');
  assert.equal(custom?.label, 'Favorite color');
  assert.equal(custom?.value, 'blue');
  assert.equal(custom?.valueType, 'text');
});

test('setDefaultLens switches the share default', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerLens(bag, 'Business');
  const biz = bag.lenses.find((l) => l.name === 'Business')!;
  bag = setDefaultLens(bag, biz.id);
  assert.equal(bag.defaultLensId, biz.id);
});

test('per-method relay defaults to the deployment host; update sticks', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'email', 'a@b.test');
  assert.ok(methodRelayHost(bag.methods[0]).length > 0);
  bag = updateOwnerMethod(bag, bag.methods[0].id, { relay: 'relay.example.test' });
  assert.equal(methodRelayHost(bag.methods[0]), 'relay.example.test');
});

test('inlined data: values are refused (avatars referenced, not inlined)', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'url', 'data:text/plain,hi');
  assert.equal(ownerCardHasInlinedBinary(bag), true);
  const saved = saveOwnerCard('bb'.repeat(20), bag);
  assert.equal(saved.ok, false);
  if (!saved.ok) assert.equal(saved.reason, 'inlined-binary');
});

test('soft cap refuses a bag over 16 KB', () => {
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'custom', 'x'.repeat(OWNER_CARD_SOFT_CAP_BYTES + 8), 'pad');
  assert.ok(ownerCardBytes(bag) > OWNER_CARD_SOFT_CAP_BYTES);
  const saved = saveOwnerCard('cc'.repeat(20), bag);
  assert.equal(saved.ok, false);
  if (!saved.ok) assert.equal(saved.reason, 'over-cap');
});
