import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLE_SVRNTY_PEERS } from './sample-svrnty-keys';

/** Classical sample names — must not receive a living key or fingerprint. */
const CLASSICAL_SAMPLE_NAMES = [
  'Lynn Conway',
  'Émilie du Châtelet',
  'Claude Shannon',
  'Hedy Lamarr',
  'Katherine Johnson',
  'Rosalind Franklin',
  'Marie Curie',
  'Nikola Tesla',
  'Hypatia',
  'Frank Garcia',
];

test('classical demo names are not in the living SVRNTY key set', () => {
  const living = new Set(SAMPLE_SVRNTY_PEERS.map((p) => p.name));
  for (const name of CLASSICAL_SAMPLE_NAMES) {
    assert.equal(living.has(name), false, `${name} must stay keyless`);
  }
});

test('living demo names cover Ada…Dorothy', () => {
  const living = SAMPLE_SVRNTY_PEERS.map((p) => p.name);
  assert.ok(living.includes('Ada Lovelace'));
  assert.ok(living.includes('Grace Hopper'));
  assert.ok(living.includes('Alan Turing'));
  assert.ok(living.includes('Dorothy Vaughan'));
  assert.equal(living.length, 10);
});
