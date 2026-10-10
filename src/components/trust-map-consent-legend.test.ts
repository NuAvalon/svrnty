import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TRUST_RECIPE_COPY } from '../lib/trust/trust-recipe';

/**
 * Queue #5 follow-up: the anti-surveillance clause is already in
 * TRUST_RECIPE_COPY.peerMeshLegend (shipped with PR #170). src/lib/trust/
 * is CODEOWNERS-fenced, so this lock lives on the render-glass side:
 * the recipe string keeps both halves, and TrustMap renders that string
 * (not a forked legend).
 */
describe('Galaxy peer-mesh legend — anti-surveillance clause', () => {
  it('legend copy carries both halves: disclosures-not-observations AND never-infers', () => {
    const legend = TRUST_RECIPE_COPY.peerMeshLegend;
    assert.match(legend, /disclosures, not observations/i);
    assert.match(legend, /never infers who knows whom/i);
  });

  it('TrustMap renders the recipe legend in the consent-legend, not a forked string', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(dir, 'TrustMap.tsx'), 'utf8');
    assert.match(src, /data-testid="trust-map-consent-legend"/);
    assert.match(src, /TRUST_RECIPE_COPY\.peerMeshLegend/);
    assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
  });
});
