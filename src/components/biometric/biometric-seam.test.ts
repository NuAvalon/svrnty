/**
 * CUR-6 biometric seam — pure helpers + stub honesty (no crypto).
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

describe('biometric-seam stubs', () => {
  it('seam is not live until Flint wires PRF', () => {
    assert.equal(isBiometricSeamLive(), false);
  });

  it('getBiometricEnrollment is never enrolled under stub', async () => {
    const state = await getBiometricEnrollment('abc123');
    assert.equal(state.enrolled, false);
  });

  it('enrollBiometric returns stub-not-live (no PRF invent)', async () => {
    const r = await enrollBiometric({ fingerprint: 'abc123', passphrase: 'x'.repeat(12) });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'stub-not-live');
  });

  it('unlockWithBiometric returns stub-not-live', async () => {
    const r = await unlockWithBiometric('abc123');
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'stub-not-live');
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
