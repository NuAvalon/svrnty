/**
 * CUR-6 biometric DEV-TEST enable — the dev/beta-only flag that lets a real authenticator
 * exercise the PRF round-trip BEFORE the live flip, WITHOUT flipping any public claim.
 *
 * The security invariant under test: biometricDevTestEnabled() may change the LOOK/ACTION, but
 * it must NEVER flip isBiometricSeamLive() (the claim gate) — so CLAIM copy + the CI claim-sweep
 * stay honest even on a dev/beta build. And it is prod-SAFE by default (env unset ⇒ false).
 */
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { biometricDevTestEnabled, isBiometricSeamLive } from './biometric-seam';
import { lockScreenDeviceUnlockLook, settingsDeviceUnlockLook } from './device-unlock-presentation';

const KEY = 'NEXT_PUBLIC_BIOMETRIC_DEVTEST';

describe('biometric dev-test enable (prod-safe, claim-honest)', () => {
  let prev: string | undefined;
  beforeEach(() => {
    prev = process.env[KEY];
    delete process.env[KEY];
  });
  afterEach(() => {
    if (prev === undefined) delete process.env[KEY];
    else process.env[KEY] = prev;
  });

  it('prod-SAFE by default: env unset ⇒ false', () => {
    assert.equal(biometricDevTestEnabled(), false);
  });

  it('true ONLY for the exact "1" opt-in; anything else ⇒ false', () => {
    process.env[KEY] = '1';
    assert.equal(biometricDevTestEnabled(), true);
    for (const v of ['0', 'true', 'yes', '', 'TRUE', '2']) {
      process.env[KEY] = v;
      assert.equal(biometricDevTestEnabled(), false, `"${v}" must not enable`);
    }
  });

  it('SECURITY: the dev flag NEVER flips the claim gate (isBiometricSeamLive stays false)', () => {
    process.env[KEY] = '1';
    assert.equal(biometricDevTestEnabled(), true);
    assert.equal(isBiometricSeamLive(), false); // claim/copy/CI-sweep stay honest
  });

  it('composition: dev flag flips the LOOK to action/enable while the claim gate is false', () => {
    process.env[KEY] = '1';
    const seamLiveForLook = isBiometricSeamLive() || biometricDevTestEnabled();
    assert.equal(seamLiveForLook, true);
    assert.equal(isBiometricSeamLive(), false);
    // lock-screen: no longer "coming-soon" — the functional action shows for the device-test.
    assert.equal(lockScreenDeviceUnlockLook({ visible: true, seamLive: seamLiveForLook }), 'action');
    // settings: enroll becomes available (capability present, not yet enrolled).
    assert.equal(
      settingsDeviceUnlockLook({ seamLive: seamLiveForLook, enrolled: false, capabilityAvailable: true }),
      'enable',
    );
  });

  it('without the dev flag, the look stays coming-soon (default honest state)', () => {
    const seamLiveForLook = isBiometricSeamLive() || biometricDevTestEnabled();
    assert.equal(seamLiveForLook, false);
    assert.equal(lockScreenDeviceUnlockLook({ visible: true, seamLive: seamLiveForLook }), 'coming-soon');
    assert.equal(
      settingsDeviceUnlockLook({ seamLive: seamLiveForLook, enrolled: false, capabilityAvailable: true }),
      'coming-soon',
    );
  });
});
