import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { isBetaIssuerProvisioned } from './is-beta-gate-on';

const KEY = 'NEXT_PUBLIC_SVRNTY_BETA_GATE';

describe('isBetaIssuerProvisioned — dogfood gap', () => {
  const prev = process.env[KEY];

  afterEach(() => {
    if (prev === undefined) delete process.env[KEY];
    else process.env[KEY] = prev;
  });

  it('is false when unset (gate-OFF dogfood — no redeem chrome)', () => {
    delete process.env[KEY];
    assert.equal(isBetaIssuerProvisioned(), false);
  });

  it('is false for any value other than 1/true', () => {
    process.env[KEY] = '0';
    assert.equal(isBetaIssuerProvisioned(), false);
    process.env[KEY] = 'yes';
    assert.equal(isBetaIssuerProvisioned(), false);
  });

  it('is true when the operator set 1 or true', () => {
    process.env[KEY] = '1';
    assert.equal(isBetaIssuerProvisioned(), true);
    process.env[KEY] = 'true';
    assert.equal(isBetaIssuerProvisioned(), true);
  });
});
