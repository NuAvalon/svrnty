import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ABOUT_COPY } from './copy';

describe('CUR-11 about copy (provisional)', () => {
  it('keeps brand + required shape', () => {
    assert.equal(ABOUT_COPY.brand, 'svrnty');
    assert.ok(ABOUT_COPY.lede.length > 20);
    assert.ok(ABOUT_COPY.sections.length >= 3);
    assert.ok(ABOUT_COPY.principles.length >= 3);
  });

  it('does not over-claim seed-only or full PQ restoration', () => {
    const blob = JSON.stringify(ABOUT_COPY).toLowerCase();
    assert.equal(blob.includes('forgot password'), false);
    assert.equal(blob.includes('post-quantum identity fully'), false);
    assert.equal(blob.includes('phrase alone'), false);
  });

  it('retains consent / no-aggregate guardrails in provisional copy', () => {
    const blob = JSON.stringify(ABOUT_COPY).toLowerCase();
    assert.ok(blob.includes('none inferred') || blob.includes('consented'));
    assert.ok(blob.includes('no scores') || blob.includes('no reputation'));
  });
});
