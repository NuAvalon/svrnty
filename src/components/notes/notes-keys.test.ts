import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isCanonicalNoteSender } from './notes-keys';

describe('canonical note sender gate (UI-only length/presence)', () => {
  it('is true only for a 64-hex fingerprint with both PQ pubs', () => {
    const fp = 'a'.repeat(64);
    assert.equal(isCanonicalNoteSender(fp, 'kem', 'sig'), true);
    assert.equal(isCanonicalNoteSender(fp, '', 'sig'), false);
    assert.equal(isCanonicalNoteSender(fp, 'kem', ''), false);
    assert.equal(isCanonicalNoteSender('a'.repeat(40), 'kem', 'sig'), false);
  });
});
