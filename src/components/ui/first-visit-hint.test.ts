import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HINT_SEEN_KEY, hintHasBeenSeen, markHintSeen } from './first-visit-hint';

function memStorage() {
  const bag = new Map<string, string>();
  return {
    getItem: (k: string) => (bag.has(k) ? bag.get(k)! : null),
    setItem: (k: string, v: string) => {
      bag.set(k, v);
    },
    removeItem: (k: string) => {
      bag.delete(k);
    },
  };
}

describe('first-visit hint memory', () => {
  beforeEach(() => {
    (globalThis as { window?: unknown }).window = {
      localStorage: memStorage(),
    };
  });

  it('starts unseen and remembers a close', () => {
    assert.equal(hintHasBeenSeen('galaxy-consent'), false);
    markHintSeen('galaxy-consent');
    assert.equal(hintHasBeenSeen('galaxy-consent'), true);
    assert.equal(hintHasBeenSeen('galaxy-empty'), false);
  });

  it('ignores junk in the store', () => {
    const w = (globalThis as { window: { localStorage: { setItem: (k: string, v: string) => void } } }).window;
    w.localStorage.setItem(HINT_SEEN_KEY, 'not-json');
    assert.equal(hintHasBeenSeen('galaxy-consent'), false);
  });
});

describe('first-visit hint glass — consent stays on the chip', () => {
  it('Galaxy consent chip keeps the none-inferred guarantee', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const map = readFileSync(join(dir, '..', 'TrustMap.tsx'), 'utf8');
    assert.match(map, /FirstVisitHint/);
    assert.match(map, /Every visible line consented — none inferred/);
    assert.match(map, /TRUST_RECIPE_COPY\.peerMeshLegend/);
    assert.match(map, /hint-toggle-galaxy-consent|id="galaxy-consent"/);
  });
});
