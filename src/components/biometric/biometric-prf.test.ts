/**
 * CUR-6 biometric seam — WebAuthn-PRF wrap/unwrap + session-path proof (Flint #168202).
 *
 * MOCKS navigator.credentials (create/get return a deterministic PRF output) and localStorage.
 * Proves the custody-bar behaviour:
 *   • enroll → unlock round-trip recovers the EXACT unlock factor (wrap → unwrap)
 *   • the recovered factor is fed into the SAME injected session path (initSessionKey seam)
 *   • a WRONG PRF output fails to unwrap (AES-GCM tag fail → no factor, no session)
 *   • getBiometricEnrollment reflects the REAL stored wrap; disable removes it
 *   • invariant #1: only the WRAP is persisted — the passphrase/PRF are never stored in clear
 *   • invariant #2 (structural): the one production session path is initSessionKey, no parallel
 *
 * ⚠ This mock proves the wrap/unwrap + session wiring ONLY. It does NOT authorise flipping
 * isBiometricSeamLive() — that requires a real authenticator (real-device / Playwright PRF).
 */
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  enrollBiometric,
  unlockWithBiometric,
  disableBiometric,
  getBiometricEnrollment,
  isBiometricSeamLive,
  __setSessionInitForTest,
  __resetSessionInitForTest,
} from './biometric-seam';

// ── in-memory localStorage shim ───────────────────────────────────────────
function installLocalStorage(): Map<string, string> {
  const map = new Map<string, string>();
  const shim = {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, String(v)),
    removeItem: (k: string) => void map.delete(k),
    clear: () => map.clear(),
  };
  Object.defineProperty(globalThis, 'localStorage', {
    value: shim,
    configurable: true,
    writable: true,
  });
  return map;
}

// ── mock navigator.credentials (WebAuthn-PRF) ───────────────────────────────
const RAW_ID = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

// The PRF bytes create()/get() will surface next. Mutate to simulate enroll vs unlock vs
// a wrong authenticator.
let currentPrf: Uint8Array = new Uint8Array(32).fill(0xa1);
// If false, create() returns NO prf (forces the enroll get()-fallback branch).
let createReturnsPrf = true;
let getCalls = 0;
let createCalls = 0;

function extResults(prf: Uint8Array | null) {
  return {
    getClientExtensionResults: () =>
      prf ? { prf: { results: { first: prf.slice().buffer } } } : {},
  };
}

function installCredentials() {
  const credentials = {
    create: async (_opts: unknown) => {
      createCalls++;
      return {
        rawId: RAW_ID.slice().buffer,
        ...extResults(createReturnsPrf ? currentPrf : null),
      };
    },
    get: async (_opts: unknown) => {
      getCalls++;
      return extResults(currentPrf);
    },
  };
  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials },
    configurable: true,
    writable: true,
  });
}

const FP = 'fp-prf-test';
const PASSPHRASE = 'correct horse battery staple';

beforeEach(() => {
  installLocalStorage();
  installCredentials();
  currentPrf = new Uint8Array(32).fill(0xa1);
  createReturnsPrf = true;
  getCalls = 0;
  createCalls = 0;
  __resetSessionInitForTest();
});

afterEach(() => {
  __resetSessionInitForTest();
});

describe('biometric PRF wrap/unwrap + session path', () => {
  it('seam stays NOT live on the mock (real-device proof required to flip)', () => {
    assert.equal(isBiometricSeamLive(), false);
  });

  it('enroll → unlock round-trip feeds the EXACT factor into the one session path', async () => {
    const seen: string[] = [];
    __setSessionInitForTest(async (pass) => void seen.push(pass));

    const enr = await enrollBiometric({ fingerprint: FP, passphrase: PASSPHRASE });
    assert.equal(enr.ok, true);

    const unlocked = await unlockWithBiometric(FP);
    assert.equal(unlocked.ok, true);
    // Invariant #2: the recovered factor is handed to initSessionKey (the injected seam),
    // exactly once, byte-identical to what was enrolled.
    assert.deepEqual(seen, [PASSPHRASE]);
    assert.ok(getCalls >= 1, 'unlock must assert via navigator.credentials.get');
  });

  it('WRONG PRF output fails to unwrap — no factor, no session established', async () => {
    const seen: string[] = [];
    __setSessionInitForTest(async (pass) => void seen.push(pass));

    const enr = await enrollBiometric({ fingerprint: FP, passphrase: PASSPHRASE });
    assert.equal(enr.ok, true);

    // A different authenticator / PRF secret → different PRF output → AEAD tag fail.
    currentPrf = new Uint8Array(32).fill(0xb2);
    const unlocked = await unlockWithBiometric(FP);
    assert.equal(unlocked.ok, false);
    if (!unlocked.ok) assert.equal(unlocked.reason, 'error');
    assert.deepEqual(seen, [], 'session path must NOT be called on a failed unwrap');
  });

  it('getBiometricEnrollment reflects the REAL stored wrap, not a UI flag', async () => {
    const before = await getBiometricEnrollment(FP);
    assert.equal(before.enrolled, false);

    const enr = await enrollBiometric({ fingerprint: FP, passphrase: PASSPHRASE });
    assert.equal(enr.ok, true);

    const after = await getBiometricEnrollment(FP);
    assert.equal(after.enrolled, true);
    if (after.enrolled) {
      assert.equal(typeof after.credentialIdHint, 'string');
      assert.ok(after.credentialIdHint.length > 0);
      assert.equal(typeof after.enrolledAt, 'string');
    }
  });

  it('disable removes the stored wrap', async () => {
    await enrollBiometric({ fingerprint: FP, passphrase: PASSPHRASE });
    assert.equal((await getBiometricEnrollment(FP)).enrolled, true);

    const d = await disableBiometric(FP);
    assert.equal(d.ok, true);
    assert.equal((await getBiometricEnrollment(FP)).enrolled, false);

    // And unlock after disable reports not-enrolled.
    const unlocked = await unlockWithBiometric(FP);
    assert.equal(unlocked.ok, false);
    if (!unlocked.ok) assert.equal(unlocked.reason, 'not-enrolled');
  });

  it('invariant #1: only the WRAP is persisted — passphrase & PRF never stored in clear', async () => {
    const store = installLocalStorage(); // fresh map we can read back
    installCredentials();
    await enrollBiometric({ fingerprint: FP, passphrase: PASSPHRASE });

    const raw = store.get('svrnty.biometric.wrap.' + FP);
    assert.ok(raw, 'a wrap record must be stored');
    const rec = JSON.parse(raw!);
    // Shape: handle + wrap + salt/nonce only.
    assert.ok(rec.credentialId && rec.wrappedFactor && rec.prfSalt && rec.hkdfSalt && rec.iv);
    assert.equal(typeof rec.enrolledAt, 'string');

    // The passphrase must not appear anywhere in the serialized record.
    assert.ok(!raw!.includes(PASSPHRASE), 'passphrase must never be stored in clear');
    // The raw PRF output (0xa1 × 32, base64) must not appear either.
    const prfB64 = Buffer.from(new Uint8Array(32).fill(0xa1)).toString('base64');
    assert.ok(!raw!.includes(prfB64), 'PRF output must never be stored');
    // The wrapped factor is ciphertext, not the plaintext.
    assert.notEqual(rec.wrappedFactor, PASSPHRASE);
  });

  it('enroll uses the get()-fallback when create() surfaces no PRF output', async () => {
    createReturnsPrf = false; // authenticator only returns PRF on assertion
    const seen: string[] = [];
    __setSessionInitForTest(async (pass) => void seen.push(pass));

    const enr = await enrollBiometric({ fingerprint: FP, passphrase: PASSPHRASE });
    assert.equal(enr.ok, true);
    assert.ok(getCalls >= 1, 'enroll must fall back to get() for PRF');

    const unlocked = await unlockWithBiometric(FP);
    assert.equal(unlocked.ok, true);
    assert.deepEqual(seen, [PASSPHRASE]);
  });
});

describe('invariant #2 (structural): the single production session path is initSessionKey', () => {
  const src = readFileSync(fileURLToPath(new URL('./biometric-seam.ts', import.meta.url)), 'utf8');

  it('the default session path dynamic-imports client-store and calls initSessionKey', () => {
    assert.match(src, /async function defaultSessionInit/);
    assert.match(src, /await import\(\s*['"]\.\.\/\.\.\/lib\/identity\/client-store['"]\s*\)/);
    assert.match(src, /mod\.initSessionKey\(/);
  });

  it('_sessionInit defaults to defaultSessionInit (no parallel production path)', () => {
    assert.match(src, /let _sessionInit:[\s\S]*?=\s*defaultSessionInit;/);
    // unlock establishes the session via the single _sessionInit call — not a second path.
    assert.match(src, /await _sessionInit\(factor\)/);
  });
});
