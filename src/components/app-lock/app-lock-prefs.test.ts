import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DEFAULT_APP_LOCK_PREFS,
  parseAppLockPrefs,
  appLockStatusLine,
} from './app-lock-prefs';

describe('parseAppLockPrefs', () => {
  it('returns defaults for null / garbage', () => {
    assert.deepEqual(parseAppLockPrefs(null), DEFAULT_APP_LOCK_PREFS);
    assert.deepEqual(parseAppLockPrefs('not-json'), DEFAULT_APP_LOCK_PREFS);
    assert.deepEqual(parseAppLockPrefs('{}'), DEFAULT_APP_LOCK_PREFS);
  });

  it('accepts valid idle + lockOnHide', () => {
    const prefs = parseAppLockPrefs(
      JSON.stringify({ idleTimeoutMinutes: 15, lockOnHide: true })
    );
    assert.equal(prefs.idleTimeoutMinutes, 15);
    assert.equal(prefs.lockOnHide, true);
  });

  it('rejects invalid idle values', () => {
    const prefs = parseAppLockPrefs(
      JSON.stringify({ idleTimeoutMinutes: 7, lockOnHide: true })
    );
    assert.equal(prefs.idleTimeoutMinutes, DEFAULT_APP_LOCK_PREFS.idleTimeoutMinutes);
    assert.equal(prefs.lockOnHide, true);
  });
});

describe('appLockStatusLine', () => {
  it('is claim-honest when idle is off', () => {
    const line = appLockStatusLine({ idleTimeoutMinutes: 0, lockOnHide: false });
    assert.match(line, /Idle auto-lock is off/i);
    assert.match(line, /Lock Now always clears keys from memory/i);
    assert.doesNotMatch(line, /Face ID|biometric|server/i);
  });

  it('mentions hide when enabled', () => {
    const line = appLockStatusLine({ idleTimeoutMinutes: 5, lockOnHide: true });
    assert.match(line, /5 minutes/i);
    assert.match(line, /leave this tab/i);
  });
});
