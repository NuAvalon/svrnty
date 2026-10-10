/**
 * CUR-6 honesty — pre-tap *look* for device unlock.
 *
 * Does not call crypto. The fleet seam (`isBiometricSeamLive`, enroll/unlock
 * bodies) stays in biometric-seam.ts. This module only decides whether the
 * glass may look like a working action.
 */

/** Visible, non-interactive label while the PRF seam is a stub. */
export const DEVICE_UNLOCK_COMING_SOON = 'Device unlock — coming soon';

export type LockScreenDeviceUnlockLook = 'hidden' | 'coming-soon' | 'action';

export type SettingsDeviceUnlockLook = 'none' | 'coming-soon' | 'enable' | 'disable';

/**
 * Lock-screen chrome: never look like "Unlock with device" while the seam
 * is not live. Passphrase remains the working path.
 */
export function lockScreenDeviceUnlockLook(args: {
  visible: boolean;
  seamLive: boolean;
}): LockScreenDeviceUnlockLook {
  if (!args.visible) return 'hidden';
  if (!args.seamLive) return 'coming-soon';
  return 'action';
}

/**
 * Settings chrome: enroll must not read as available/"on" while the seam
 * is not live. Disable remains if a real enrollment exists.
 */
export function settingsDeviceUnlockLook(args: {
  seamLive: boolean;
  enrolled: boolean;
  capabilityAvailable: boolean;
}): SettingsDeviceUnlockLook {
  if (args.enrolled) return 'disable';
  if (!args.capabilityAvailable) return 'none';
  if (!args.seamLive) return 'coming-soon';
  return 'enable';
}
