import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractFingerprintFromScan,
  fingerprintsMatch,
} from './fingerprint-from-scan';
import { formatFingerprintForVerify } from '../../lib/trust/trust-recipe';

const FP64 = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';
const FP40 = 'c1a00e0000000000000000000000000000000004';
const OTHER64 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

describe('extractFingerprintFromScan', () => {
  it('accepts raw 64-hex and grouped formatFingerprintForVerify output', () => {
    assert.equal(extractFingerprintFromScan(FP64), FP64);
    assert.equal(extractFingerprintFromScan(FP64.toUpperCase()), FP64);
    assert.equal(extractFingerprintFromScan(formatFingerprintForVerify(FP64)), FP64);
    assert.equal(extractFingerprintFromScan(FP40), FP40);
    assert.equal(
      extractFingerprintFromScan('068A 9927 D57F 49D8 BD1D CD38 8E5B 3F28'),
      '068a9927d57f49d8bd1dcd388e5b3f28',
    );
  });

  it('accepts JSON.fingerprint and ?fp= query, never the URL hash', () => {
    assert.equal(extractFingerprintFromScan(JSON.stringify({ fingerprint: FP64 })), FP64);
    assert.equal(
      extractFingerprintFromScan(`https://svrnty.is/card?fp=${FP64}`),
      FP64,
    );
    assert.equal(
      extractFingerprintFromScan(`https://svrnty.is/c/abc123#${FP64}`),
      null,
    );
  });

  it('rejects invite URLs, junk, and non-strings without throwing', () => {
    assert.equal(extractFingerprintFromScan('https://svrnty.is/c/abc123#deadbeef'), null);
    assert.equal(extractFingerprintFromScan('javascript:alert(1)'), null);
    assert.equal(extractFingerprintFromScan(''), null);
    assert.equal(extractFingerprintFromScan(null), null);
    assert.equal(extractFingerprintFromScan(42), null);
  });
});

describe('fingerprintsMatch — wiring gate', () => {
  it('matches byte-equal fingerprints after normalize; mismatch cannot pass', () => {
    assert.equal(fingerprintsMatch(FP64, FP64), true);
    assert.equal(fingerprintsMatch(FP64, formatFingerprintForVerify(FP64)), true);
    assert.equal(fingerprintsMatch(FP64, OTHER64), false);
    assert.equal(fingerprintsMatch(FP64, null), false);
    assert.equal(fingerprintsMatch(FP64, FP40), false);
    assert.equal(fingerprintsMatch(FP64, FP64.slice(0, 16)), false);
    assert.equal(
      fingerprintsMatch('068a9927-d57f-49d8-bd1d-cd388e5b3f28', '068a9927d57f49d8bd1dcd388e5b3f28'),
      true,
    );
  });
});
