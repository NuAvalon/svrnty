// src/lib/claim-gates.test.ts
//
// GUARDS the claim gates: any capability NOT yet wired must read false. If a wiring PR flips a gate to
// true, it MUST update the matching assertion here — that is the copy⇔reality lockstep. A gate flipped
// AHEAD of its wire (a dishonest "protected"/"live" claim) turns this suite RED. Mirrors
// components/biometric/biometric-seam.test.ts ("seam is not live until Flint wires PRF").
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isPQEncapLive, isPQSignLive, isPQWireLive, isBiometricSeamLive, isPSIDiscoveryLive } from './claim-gates';

describe('claim-gates — honest until wired (flip WITH the wire, never ahead)', () => {
  it('isPQEncapLive is false until hybridEncapsulate has a real caller (classical seal today)', () => {
    assert.equal(isPQEncapLive(), false);
  });

  it('isPQSignLive is false until buildSignedIdentityCard threads the PQ secret (classical-signed today)', () => {
    assert.equal(isPQSignLive(), false);
  });

  it('isPQWireLive is false unless BOTH encap and sign are live', () => {
    assert.equal(isPQWireLive(), false);
  });

  it('isBiometricSeamLive is re-exported and false until the WebAuthn/PRF seam is wired', () => {
    assert.equal(isBiometricSeamLive(), false);
  });

  it('isPSIDiscoveryLive is false by default (prod: NEXT_PUBLIC_PSI_DISCOVERY_LIVE unset → dormant/honest until e2e+at-rest verified)', () => {
    delete process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE;
    assert.equal(isPSIDiscoveryLive(), false);
  });

  it('isPSIDiscoveryLive reads NEXT_PUBLIC_PSI_DISCOVERY_LIVE (the DEV build enables it for QA; prod leaves it unset)', () => {
    process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE = 'true';
    try {
      assert.equal(isPSIDiscoveryLive(), true);
    } finally {
      delete process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE;
    }
  });
});
