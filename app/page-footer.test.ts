import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('site footer', () => {
  it('does not render the manifesto closer', () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'page.tsx'), 'utf8');
    assert.match(src, /TRUST_RECIPE_COPY\.manifestoWord/);
    assert.match(src, /TRUST_RECIPE_COPY\.manifestoKeep/);
    assert.match(src, /TRUST_RECIPE_COPY\.manifestoAxes/);
    assert.doesNotMatch(src, /TRUST_RECIPE_COPY\.manifestoCloser/);
    assert.doesNotMatch(src, /you are not a product/i);
  });
});
