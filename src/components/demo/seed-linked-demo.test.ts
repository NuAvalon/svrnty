import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LINKED_DEMO_VAULTS } from './seed-linked-demo';

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
  'Ada Lovelace',
  'Grace Hopper',
  'Alan Turing',
  'Margaret Hamilton',
];

describe('linked demo seed — extra vaults stay off the keyless sample set', () => {
  it('demo vault names are distinct from sample-circle people', () => {
    for (const vault of LINKED_DEMO_VAULTS) {
      assert.equal(CLASSICAL_SAMPLE_NAMES.includes(vault.name), false);
    }
  });

  it('mints vaults instead of importing SAMPLE_SVRNTY_PEERS', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(dir, 'seed-linked-demo.ts'), 'utf8');
    assert.equal(/from ['"]@\/lib\/trust\/sample-svrnty-keys['"]/.test(src), false);
    assert.match(src, /generateIdentity/);
    assert.match(src, /seedSampleCircle/);
    assert.match(src, /canonical-only/);
  });
});
