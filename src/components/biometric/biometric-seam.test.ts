/**
 * CUR-6 biometric seam — pure helpers + fail-closed contract in a headless env.
 *
 * These run under `node:test` (no jsdom / no WebAuthn / no IndexedDB), so they cover the
 * NON-crypto surface + the fail-closed early returns when the platform is unavailable:
 *   - isBiometricSeamLive() defaults false when NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE is unset (invariant 5 — never decorative-live); reads true ONLY for a build with the env === 'true'.
 *   - enroll returns 'unsupported' (no WebAuthn/IndexedDB present) — never throws, never wraps.
 *   - unlock returns 'not-enrolled' (no local blob store) — falls through to passphrase.
 *   - getBiometricEnrollment reflects real (absent) blob presence, not the UI preference.
 * The full PRF→HKDF→AES-GCM enroll→unlock round-trip is verified on a REAL platform
 * authenticator by Athena (device QA) before isBiometricSeamLive() is ever flipped true.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  biometricStatusLine,
  enrollBiometric,
  getBiometricEnrollment,
  isBiometricSeamLive,
  unlockWithBiometric,
  writeEnrollPreference,
  readEnrollPreference,
  disableBiometric,
  type BiometricCapability,
} from './biometric-seam';

describe('biometric-seam fail-closed contract (headless)', () => {
  it('seam is NOT live by default (env unset) — gated on the env flag + Flint co-verify + Athena device test', () => {
    delete process.env.NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE;
    assert.equal(isBiometricSeamLive(), false);
  });

  it('seam reads live ONLY when NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE === "true" (dev-test opt-in; strict, not truthy)', () => {
    process.env.NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE = 'true';
    assert.equal(isBiometricSeamLive(), true);
    process.env.NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE = '1'; // truthy but not exactly 'true' → still false
    assert.equal(isBiometricSeamLive(), false);
    delete process.env.NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE;
    assert.equal(isBiometricSeamLive(), false);
  });

  it('getBiometricEnrollment reflects real (absent) blob — not the UI preference', async () => {
    const state = await getBiometricEnrollment('abc123');
    assert.equal(state.enrolled, false);
  });

  it('enrollBiometric fails unsupported with no WebAuthn/IndexedDB (never wraps, never throws)', async () => {
    const r = await enrollBiometric({ fingerprint: 'abc123', passphrase: 'x'.repeat(12) });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'unsupported');
  });

  it('unlockWithBiometric fails closed (not-enrolled) with no local blob store', async () => {
    const r = await unlockWithBiometric('abc123');
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'not-enrolled');
  });

  it('enroll preference is local UI-only', () => {
    // jsdom-less: localStorage may be absent in node — helpers must not throw
    writeEnrollPreference('fp-test', true);
    const v = readEnrollPreference('fp-test');
    assert.equal(typeof v, 'boolean');
    writeEnrollPreference('fp-test', false);
  });

  it('disableBiometric clears preference', async () => {
    writeEnrollPreference('fp-disable', true);
    const r = await disableBiometric('fp-disable');
    assert.equal(r.ok, true);
    assert.equal(readEnrollPreference('fp-disable'), false);
  });
});

describe('biometricStatusLine claim-honesty', () => {
  const available: BiometricCapability = { status: 'available' };

  it('unavailable — no platform authenticator', () => {
    const line = biometricStatusLine({
      capability: { status: 'unavailable', reason: 'no-platform-authenticator' },
      enrollment: { enrolled: false },
      seamLive: false,
    });
    assert.match(line, /no built-in unlock/i);
  });

  it('available + seam not live — passphrase remains', () => {
    const line = biometricStatusLine({
      capability: available,
      enrollment: { enrolled: false },
      seamLive: false,
    });
    assert.match(line, /Passphrase unlock stays available/i);
    assert.doesNotMatch(line, /fully restored|keys are unlocked by Face ID/i);
  });

  it('available + seam live + enrolled', () => {
    const line = biometricStatusLine({
      capability: available,
      enrollment: {
        enrolled: true,
        credentialIdHint: '…abcd',
        enrolledAt: '2026-08-30T00:00:00.000Z',
      },
      seamLive: true,
    });
    assert.match(line, /Device unlock is on/i);
  });
});
