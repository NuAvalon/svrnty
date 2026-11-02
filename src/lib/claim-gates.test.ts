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

/** Runs fn with the build domain (NEXT_PUBLIC_SVRNTY_DOMAIN) set to `value`, or unset when undefined. */
function withPsiEnv(value: string | undefined, fn: () => void): void {
  const prev = process.env.NEXT_PUBLIC_SVRNTY_DOMAIN;
  if (value === undefined) delete process.env.NEXT_PUBLIC_SVRNTY_DOMAIN;
  else process.env.NEXT_PUBLIC_SVRNTY_DOMAIN = value;
  try {
    fn();
  } finally {
    if (prev === undefined) delete process.env.NEXT_PUBLIC_SVRNTY_DOMAIN;
    else process.env.NEXT_PUBLIC_SVRNTY_DOMAIN = prev;
  }
}

describe('claim-gates — honest until wired (flip WITH the wire, never ahead)', () => {
  it('isPQEncapLive is false until hybridEncapsulate has a real caller (classical seal today)', () => {
    assert.equal(isPQEncapLive(), false);
  });

  it('isPQSignLive is false until buildSignedIdentityCard threads the PQ secret (classical-signed today)', () => {
    assert.equal(isPQSignLive(), false);
  });

  it('isPQWireLive (PSI-discovery transport PQ) tracks isPSIDiscoveryLive; decoupled from the messaging encap/sign gates', () => {
    // The discovery /initiate wire is PQ by construction (apex-proven); the CLAIM lights WITH discovery, per BUILD (a dev.* domain).
    // A build without the flag (prod) is dark: neither gate is true. Both move together (one flag); encap/sign stay false (decoupled).
    withPsiEnv(undefined, () => {
      assert.equal(isPQWireLive(), false);
      assert.equal(isPQWireLive(), isPSIDiscoveryLive());
    });
    withPsiEnv('dev.svrnty.is', () => {
      assert.equal(isPQWireLive(), true);
      assert.equal(isPQWireLive(), isPSIDiscoveryLive());
    });
  });

  it('isBiometricSeamLive is re-exported and false until the WebAuthn/PRF seam is wired', () => {
    assert.equal(isBiometricSeamLive(), false);
  });

  it('isPSIDiscoveryLive is per BUILD: live only in a DEV build (domain "dev.*"); an unset domain is prod = dark (prod has no satellite pin) — direct-block-only scope', () => {
    withPsiEnv(undefined, () => assert.equal(isPSIDiscoveryLive(), false, 'unset domain = prod = PSI off (Archie #2601)'));
    withPsiEnv('dev.svrnty.is', () => assert.equal(isPSIDiscoveryLive(), true));
    withPsiEnv('svrnty.is', () => assert.equal(isPSIDiscoveryLive(), false));
    withPsiEnv('example.com', () => assert.equal(isPSIDiscoveryLive(), false, 'a self-hoster has no pin either'));
    withPsiEnv('', () => assert.equal(isPSIDiscoveryLive(), false));
  });

  it('isPiece2MutualBlockLive is FALSE until emit/receive transport + §F3 churn-matrix land (spine mechanism built but inert — transitive block not yet live)', () => {
    assert.equal(isPiece2MutualBlockLive(), false);
  });

  it('TrustMap empty-state trust copy is the honest "coming" sentence ONLY: no mutual sentence, no gate import (G-6 lockstep, Flint lane:svrnty #136 / Hypatia #924)', () => {
    // #593 removed the affirm wire and the B merge kept exactly one empty-state panel, so the dormant gated ternary (whose true arm, "Trust is mutual,
    // after you make sure it's them.", was a G-6 overclaim one flag-flip from rendering) is GONE. Static check on the source: the honest sentence
    // appears exactly once, the mutual sentence zero times, and TrustMap does not import the gate. When PSI (#588) adds a gated arm, it gets a NEW
    // lockstep test here; do not loosen this one.
    const src = readFileSync(join(__dirname, '../components/TrustMap.tsx'), 'utf8');
    // JSX source form: the apostrophe is the &apos; entity in the file (it renders as ').
    assert.equal(src.split('Make sure it&apos;s them before you trust. Mutual confirmation is coming.').length - 1, 1,
      'the honest "coming" sentence appears exactly once');
    assert.equal(src.split('Trust is mutual').length - 1, 0, "no 'Trust is mutual' string anywhere in TrustMap.tsx");
    assert.doesNotMatch(src, /isMutualTrustWireLive/, 'TrustMap.tsx must not reference the mutual-wire gate until #588 adds a gated arm with its own lockstep test');
  });

  it('isMutualTrustWireLive is FALSE until the FE deposit-hook + the two-seat e2e land (crypto built both sides, consume wired, but no FE deposit path yet — flip WITH the e2e-green proof)', () => {
    assert.equal(isMutualTrustWireLive(), false);
  });

  it('isRelayMigrateLive is FALSE until migrateRelay + config override + card re-sign are wired', () => {
    assert.equal(isRelayMigrateLive(), false);
  });
});
