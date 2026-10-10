import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('contact card verbs share one size', () => {
  it('Chat, Send update, and Actions use cardVerbBtnStyle', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const card = readFileSync(join(dir, 'ContactActionCard.tsx'), 'utf8');
    const menu = readFileSync(join(dir, '..', 'ui', 'CardActionMenu.tsx'), 'utf8');
    assert.match(card, /cardVerbBtnStyle\(\)/);
    assert.match(card, /cardVerbBtnStyle\(\{ muted: true \}\)/);
    assert.match(card, /alignItems: 'stretch'/);
    assert.match(menu, /export function cardVerbBtnStyle/);
    assert.match(menu, /minHeight: 40/);
    assert.match(menu, /return cardVerbBtnStyle\(\{ open \}\)/);
  });
});
