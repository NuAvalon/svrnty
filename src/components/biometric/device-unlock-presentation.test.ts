/**
 * Device-unlock pre-tap honesty (presentation only — no seam body changes).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isBiometricSeamLive } from './biometric-seam';
import {
  DEVICE_UNLOCK_COMING_SOON,
  lockScreenDeviceUnlockLook,
  settingsDeviceUnlockLook,
} from './device-unlock-presentation';

describe('device-unlock coming-soon copy', () => {
  it('does not claim the feature is live or on', () => {
    assert.equal(DEVICE_UNLOCK_COMING_SOON, 'Device unlock — coming soon');
    assert.doesNotMatch(DEVICE_UNLOCK_COMING_SOON, /\bon\b|unlock with device|enable/i);
  });
});

describe('lockScreenDeviceUnlockLook', () => {
  it('hides when the parent did not mount chrome', () => {
    assert.equal(lockScreenDeviceUnlockLook({ visible: false, seamLive: false }), 'hidden');
    assert.equal(lockScreenDeviceUnlockLook({ visible: false, seamLive: true }), 'hidden');
  });

  it('is coming-soon while the fleet seam is a stub (today)', () => {
    assert.equal(isBiometricSeamLive(), false);
    assert.equal(
      lockScreenDeviceUnlockLook({ visible: true, seamLive: isBiometricSeamLive() }),
      'coming-soon'
    );
    assert.notEqual(
      lockScreenDeviceUnlockLook({ visible: true, seamLive: isBiometricSeamLive() }),
      'action'
    );
  });

  it('is an unlock action only when the seam is live', () => {
    assert.equal(lockScreenDeviceUnlockLook({ visible: true, seamLive: true }), 'action');
  });
});

describe('settingsDeviceUnlockLook', () => {
  it('never offers enroll while the seam is not live', () => {
    assert.equal(
      settingsDeviceUnlockLook({
        seamLive: false,
        enrolled: false,
        capabilityAvailable: true,
      }),
      'coming-soon'
    );
  });

  it('offers enable only when live + available + not enrolled', () => {
    assert.equal(
      settingsDeviceUnlockLook({
        seamLive: true,
        enrolled: false,
        capabilityAvailable: true,
      }),
      'enable'
    );
  });

  it('shows disable when enrolled (turn-off remains available)', () => {
    assert.equal(
      settingsDeviceUnlockLook({
        seamLive: true,
        enrolled: true,
        capabilityAvailable: true,
      }),
      'disable'
    );
  });

  it('shows nothing extra when the platform authenticator is absent', () => {
    assert.equal(
      settingsDeviceUnlockLook({
        seamLive: false,
        enrolled: false,
        capabilityAvailable: false,
      }),
      'none'
    );
  });
});
