import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('distress vivre sits on the card', () => {
  it('ContactActionCard always paints VivreBurn when distress, not only when expanded', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const card = readFileSync(join(dir, 'ContactActionCard.tsx'), 'utf8');
    const book = readFileSync(join(dir, 'MasterAddressBookList.tsx'), 'utf8');
    assert.match(card, /distress \? \(/);
    assert.match(card, /<VivreBurn \/>/);
    assert.match(card, /position: 'relative'/);
    assert.doesNotMatch(card, /sheetExpanded \? <VivreBurn/);
    assert.match(book, /row\.distress \? <VivreBurn compact/);
  });
});
