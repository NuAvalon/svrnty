import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('distress vivre sits on the card', () => {
  it('ContactActionCard still mounts VivreBurn (not gutted) but paint is Flint-gated', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const card = readFileSync(join(dir, 'ContactActionCard.tsx'), 'utf8');
    const book = readFileSync(join(dir, 'MasterAddressBookList.tsx'), 'utf8');
    const burn = readFileSync(join(dir, '..', 'VivreBurn.tsx'), 'utf8');
    assert.match(card, /paintInboundDistress\(distress\)/);
    assert.match(card, /<VivreBurn \/>/);
    assert.match(card, /position: 'relative'/);
    assert.doesNotMatch(card, /sheetExpanded \? <VivreBurn/);
    assert.match(book, /paintInboundDistress\(!!row\.distress\)/);
    assert.match(book, /showDistress \? <VivreBurn compact/);
    assert.match(burn, /if \(!isInboundDistressPaintLive\(\)\) return null/);
    const gate = readFileSync(join(dir, '..', 'vivre-paint-gate.ts'), 'utf8');
    assert.match(gate, /return false/);
  });
});
