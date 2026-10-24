// src/lib/claim-gates.test.ts
//
// GUARDS the claim gates: any capability NOT yet wired must read false. If a wiring PR flips a gate to
// true, it MUST update the matching assertion here — that is the copy⇔reality lockstep. A gate flipped
// AHEAD of its wire (a dishonest "protected"/"live" claim) turns this suite RED. Mirrors
// components/biometric/biometric-seam.test.ts ("seam is not live until Flint wires PRF").
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isPQEncapLive, isPQSignLive, isPQWireLive, isBiometricSeamLive, isPSIDiscoveryLive, isPiece2MutualBlockLive, isMutualTrustWireLive, isRelayMigrateLive } from './claim-gates';

describe('claim-gates — honest until wired (flip WITH the wire, never ahead)', () => {
  it('isPQEncapLive is false until hybridEncapsulate has a real caller (classical seal today)', () => {
    assert.equal(isPQEncapLive(), false);
  });

  it('isPQSignLive is false until buildSignedIdentityCard threads the PQ secret (classical-signed today)', () => {
    assert.equal(isPQSignLive(), false);
  });

  it('isPQWireLive (PSI-discovery transport PQ) tracks isPSIDiscoveryLive — LIVE as of the dev flip; decoupled from the messaging encap/sign gates', () => {
    // The discovery /initiate wire is PQ by construction (apex-proven); the CLAIM lights WITH discovery.
    // isPSIDiscoveryLive() is true as of the dev flip → this is true. Both move together (one flag);
    // the messaging encap/sign gates stay false (decoupled).
    assert.equal(isPQWireLive(), true);
    assert.equal(isPQWireLive(), isPSIDiscoveryLive());
  });

  it('isBiometricSeamLive is re-exported and false until the WebAuthn/PRF seam is wired', () => {
    assert.equal(isBiometricSeamLive(), false);
  });

  it('isPSIDiscoveryLive is TRUE as of the dev flip (e2e verify + Flint at-rest co-verify + Peter informed reconfirm) — direct-block-only scope', () => {
    assert.equal(isPSIDiscoveryLive(), true);
  });

  it('isPiece2MutualBlockLive is FALSE until emit/receive transport + §F3 churn-matrix land (spine mechanism built but inert — transitive block not yet live)', () => {
    assert.equal(isPiece2MutualBlockLive(), false);
  });

  it('TrustMap empty-state trust copy is GATED on isMutualTrustWireLive (G-6 lockstep, Flint lane:svrnty #136)', () => {
    // Flipping isMutualTrustWireLive must flip this string too: the "mutual" sentence may only render
    // in the true-arm; today (gate false) users see the honest "coming" arm. Static check on the source.
    const src = readFileSync(join(__dirname, '../components/TrustMap.tsx'), 'utf8');
    assert.ok(src.includes(`{isMutualTrustWireLive() ? "Trust is mutual, after you make sure it's them." : "Make sure it's them before you trust. Mutual confirmation is coming."}`),
      'TrustMap.tsx empty-state copy must be the isMutualTrustWireLive() ternary');
    assert.equal(src.split("Trust is mutual, after you make sure it").length - 1, 1, 'the mutual sentence appears exactly once (in the true-arm)');
  });

  it('isMutualTrustWireLive is FALSE until the FE deposit-hook + the two-seat e2e land (crypto built both sides, consume wired, but no FE deposit path yet — flip WITH the e2e-green proof)', () => {
    assert.equal(isMutualTrustWireLive(), false);
  });

  it('isRelayMigrateLive is FALSE until migrateRelay + config override + card re-sign are wired', () => {
    assert.equal(isRelayMigrateLive(), false);
  });
});
