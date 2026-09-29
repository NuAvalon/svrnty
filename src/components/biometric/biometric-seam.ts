/**
 * CUR-6 · L5 biometric unlock — fleet seam (thin UI contract).
 *
 * ⛔ PRF / wrapping-key / WebAuthn credential crypto = Flint.
 * This module:
 *   - probes browser platform-authenticator *availability* (not crypto)
 *   - declares the hook signatures the glass calls
 *   - stubs enroll / unlock / disable until Flint wires PRF → session unwrap
 *
 * NEVER derive session keys, store wrap material, or call credentials.create
 * with a PRF extension from UI code. Replace stub bodies only.
 */

export type BiometricCapability =
  | { status: 'available' }
  | {
      status: 'unavailable';
      reason: 'no-platform-authenticator' | 'insecure-context' | 'unsupported';
    };

export type BiometricEnrollmentState =
  | { enrolled: false }
  | {
      enrolled: true;
      /** Short non-secret hint for UI only (never a key). */
      credentialIdHint: string;
      enrolledAt: string;
    };

export type EnrollBiometricResult =
  | { ok: true; credentialIdHint: string }
  | {
      ok: false;
      reason:
        | 'stub-not-live'
        | 'cancelled'
        | 'unsupported'
        | 'wrong-passphrase'
        | 'error';
      message?: string;
    };

export type UnlockWithBiometricResult =
  | { ok: true }
  | {
      ok: false;
      reason:
        | 'stub-not-live'
        | 'cancelled'
        | 'not-enrolled'
        | 'unsupported'
        | 'error';
      message?: string;
    };

export type DisableBiometricResult =
  | { ok: true }
  | { ok: false; reason: 'stub-not-live' | 'not-enrolled' | 'error'; message?: string };

const ENROLL_PREF_PREFIX = 'svrnty.biometric.enroll-pref.';

/** UI-only preference: user asked to enable device unlock (does NOT mean PRF is live). */
export function readEnrollPreference(fingerprint: string): boolean {
  if (typeof localStorage === 'undefined') return false;
  try {
    return localStorage.getItem(ENROLL_PREF_PREFIX + fingerprint) === '1';
  } catch {
    return false;
  }
}

export function writeEnrollPreference(fingerprint: string, want: boolean): void {
  if (typeof localStorage === 'undefined') return;
  try {
    if (want) localStorage.setItem(ENROLL_PREF_PREFIX + fingerprint, '1');
    else localStorage.removeItem(ENROLL_PREF_PREFIX + fingerprint);
  } catch {
    /* ignore quota / private mode */
  }
}

/**
 * Browser capability probe — NOT crypto.
 * Uses WebAuthn platform-authenticator availability only.
 */
export async function probeBiometricCapability(): Promise<BiometricCapability> {
  if (typeof window === 'undefined') {
    return { status: 'unavailable', reason: 'unsupported' };
  }
  if (!window.isSecureContext) {
    return { status: 'unavailable', reason: 'insecure-context' };
  }
  const PK = typeof PublicKeyCredential !== 'undefined' ? PublicKeyCredential : null;
  if (!PK || typeof PK.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
    return { status: 'unavailable', reason: 'unsupported' };
  }
  try {
    const ok = await PK.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!ok) return { status: 'unavailable', reason: 'no-platform-authenticator' };
    return { status: 'available' };
  } catch {
    return { status: 'unavailable', reason: 'unsupported' };
  }
}

/**
 * Fleet: return whether a PRF-backed credential is enrolled for this fingerprint.
 * Stub: never enrolled (no crypto wrap stored by UI).
 */
export async function getBiometricEnrollment(
  _fingerprint: string
): Promise<BiometricEnrollmentState> {
  return { enrolled: false };
}

/**
 * Fleet: create WebAuthn credential + PRF-wrap a session unlock factor.
 * Requires passphrase confirmation so wrap can be sealed while session is open.
 * Stub: refuses — do not invent PRF wrapping in the glass.
 */
export async function enrollBiometric(_args: {
  fingerprint: string;
  passphrase: string;
}): Promise<EnrollBiometricResult> {
  return {
    ok: false,
    reason: 'stub-not-live',
    message:
      'Device unlock is not live yet — passphrase remains your unlock. (Flint PRF seam pending.)',
  };
}

/**
 * Fleet: WebAuthn get + PRF unwrap → initSessionKey equivalent.
 * Stub: refuses. Lock screen must fall through to passphrase.
 */
export async function unlockWithBiometric(
  _fingerprint: string
): Promise<UnlockWithBiometricResult> {
  return {
    ok: false,
    reason: 'stub-not-live',
    message:
      'Device unlock is not live yet. Enter your passphrase to unlock.',
  };
}

/**
 * Fleet: revoke local credential + clear wrap.
 * Stub: no-op success for preference clear; honest stub if "enrolled" path ever set.
 */
export async function disableBiometric(
  fingerprint: string
): Promise<DisableBiometricResult> {
  writeEnrollPreference(fingerprint, false);
  return { ok: true };
}

/** Claim-honest helper copy for capability / stub states. */
export function biometricStatusLine(args: {
  capability: BiometricCapability;
  enrollment: BiometricEnrollmentState;
  seamLive: boolean;
}): string {
  if (args.capability.status === 'unavailable') {
    switch (args.capability.reason) {
      case 'insecure-context':
        return 'Device unlock needs a secure (HTTPS) context.';
      case 'no-platform-authenticator':
        return 'This device has no built-in unlock (Face ID / fingerprint / screen lock).';
      default:
        return 'Device unlock is not supported in this browser.';
    }
  }
  if (!args.seamLive) {
    return 'Passphrase unlock stays available. Device unlock activates when the crypto seam is live.';
  }
  if (args.enrollment.enrolled) {
    return 'Device unlock is on for this identity on this device.';
  }
  return 'Use your device unlock (Face ID, fingerprint, or screen lock) so you are not typing a passphrase every time.';
}

/** Stub is the only implementation until Flint replaces enroll/unlock bodies. */
export function isBiometricSeamLive(): boolean {
  return false;
}
