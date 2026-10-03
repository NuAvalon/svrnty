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

  it('isPQWireLive (PSI-discovery transport PQ) tracks isPSIDiscoveryLive — dark today; decoupled from the messaging encap/sign gates', () => {
    // The discovery /initiate wire is PQ by construction (apex-proven), but the CLAIM only lights WHEN
    // discovery is live. isPSIDiscoveryLive() is false today → this stays false. At the flip, whoever
    // flips isPSIDiscoveryLive true MUST update BOTH this assertion and the isPSIDiscoveryLive one.
    assert.equal(isPQWireLive(), false);
    assert.equal(isPQWireLive(), isPSIDiscoveryLive());
  });

  it('isBiometricSeamLive is re-exported and false until the WebAuthn/PRF seam is wired', () => {
    assert.equal(isBiometricSeamLive(), false);
  });

  it('isPSIDiscoveryLive is false until the PSI wire-in passes e2e verify + Flint at-rest co-verify (do-not-advertise)', () => {
    assert.equal(isPSIDiscoveryLive(), false);
  });
});
