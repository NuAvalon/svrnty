/**
 * CUR-6 · L5 biometric unlock — fleet seam (WebAuthn-PRF key custody).
 *
 * Flint (#168202) wired the PRF → session-unwrap crypto. Custody bar (HARD):
 *   1. STORE THE WRAP, NEVER THE KEY. Only { credentialId, wrappedFactor, salt/nonce }
 *      is persisted. The raw unlock factor (the passphrase) is NEVER written in the clear.
 *      The PRF output is re-derived at use-time from the authenticator and NEVER stored.
 *   2. PRF-unwrap feeds the SAME `initSessionKey` path passphrase-unlock uses — ONE session
 *      path, no parallel privileged unlock (see `defaultSessionInit`).
 *   3. `getBiometricEnrollment` reflects a REAL stored wrap, not a UI preference flag.
 *   4. AEAD (AES-GCM) wrap, fresh nonce; wrap-key = HKDF(PRF output). Standard WebCrypto only.
 *
 * ⚠ `isBiometricSeamLive()` still returns FALSE: the wrap/unwrap + session-path logic is
 * unit-proven against a mocked authenticator, but the LIVE flip requires a real-device /
 * Playwright PRF proof (actual platform authenticator). Do NOT flip on the mock alone.
 *
 * NEVER derive session keys, store wrap material, or call credentials.create with a PRF
 * extension from UI code — that stays here, behind these four hooks.
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

// ──────────────────────────────────────────────────────────────────────────
// Custody: the stored WRAP record (invariant #1).
// Everything here is non-secret EXCEPT `wrappedFactor`, which is AES-GCM ciphertext
// of the unlock factor and is useless without the authenticator-held PRF secret.
// The passphrase (unlock factor) and the PRF output are NEVER persisted.
// ──────────────────────────────────────────────────────────────────────────

const WRAP_STORE_PREFIX = 'svrnty.biometric.wrap.';
const WRAP_ENC_VERSION = 1;
/** HKDF domain-separation label for the PRF→wrap-key derivation. */
const HKDF_INFO = 'svrnty/biometric/prf-wrap/v1';

interface StoredBiometricWrap {
  enc_version: number;
  /** base64url of the WebAuthn credential rawId — a non-secret handle. */
  credentialId: string;
  /** base64 PRF-eval input (non-secret); MUST match at enroll & unlock so PRF output matches. */
  prfSalt: string;
  /** base64 HKDF salt (non-secret). */
  hkdfSalt: string;
  /** base64 AES-GCM nonce (non-secret). */
  iv: string;
  /** base64 AES-GCM ciphertext of the unlock factor — the ONLY secret-bearing field, encrypted. */
  wrappedFactor: string;
  enrolledAt: string;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(b64u: string): Uint8Array {
  const pad = b64u.length % 4 === 0 ? '' : '='.repeat(4 - (b64u.length % 4));
  return fromBase64(b64u.replace(/-/g, '+').replace(/_/g, '/') + pad);
}

function readWrap(fingerprint: string): StoredBiometricWrap | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    const raw = localStorage.getItem(WRAP_STORE_PREFIX + fingerprint);
    if (!raw) return null;
    const rec = JSON.parse(raw) as StoredBiometricWrap;
    // A record counts as a real enrollment ONLY if it carries both the handle and the wrap.
    if (!rec || !rec.credentialId || !rec.wrappedFactor) return null;
    if (rec.enc_version !== WRAP_ENC_VERSION) return null;
    return rec;
  } catch {
    return null;
  }
}

function writeWrap(fingerprint: string, rec: StoredBiometricWrap): void {
  if (typeof localStorage === 'undefined') {
    throw new Error('No persistent store available for biometric wrap');
  }
  localStorage.setItem(WRAP_STORE_PREFIX + fingerprint, JSON.stringify(rec));
}

function removeWrap(fingerprint: string): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.removeItem(WRAP_STORE_PREFIX + fingerprint);
  } catch {
    /* ignore */
  }
}

/** Non-secret UI hint derived from the credential handle. */
function credentialIdHint(credentialId: string): string {
  const tail = credentialId.length <= 6 ? credentialId : credentialId.slice(-6);
  return '…' + tail;
}

// ──────────────────────────────────────────────────────────────────────────
// Crypto (invariant #4): wrap-key = HKDF-SHA256(PRF output); AEAD = AES-GCM-256.
// ──────────────────────────────────────────────────────────────────────────

async function deriveWrapKey(prfOutput: Uint8Array, hkdfSalt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: hkdfSalt,
      info: new TextEncoder().encode(HKDF_INFO),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt']
  );
}

interface WrapOutput {
  hkdfSalt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

/** WRAP the unlock factor under HKDF(PRF). Fresh salt + nonce each time. */
async function wrapFactor(prfOutput: Uint8Array, factor: string): Promise<WrapOutput> {
  const hkdfSalt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveWrapKey(prfOutput, hkdfSalt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(factor)
    )
  );
  return { hkdfSalt, iv, ciphertext };
}

/** UNWRAP the factor. A wrong PRF output ⇒ wrong wrap-key ⇒ AEAD tag fail ⇒ throw. */
async function unwrapFactor(
  prfOutput: Uint8Array,
  hkdfSalt: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<string> {
  const key = await deriveWrapKey(prfOutput, hkdfSalt);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  );
  return new TextDecoder().decode(plaintext);
}

// ──────────────────────────────────────────────────────────────────────────
// WebAuthn-PRF boundary. Reads `navigator.credentials` directly (the real browser
// path); unit tests mock `navigator.credentials` + `PublicKeyCredential`.
// ──────────────────────────────────────────────────────────────────────────

/** PRF extension output shape (the DOM lib may predate the PRF extension — kept local). */
interface PrfExtensionOutputs {
  prf?: { results?: { first?: BufferSource } };
}

function webAuthnAvailable(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    !!navigator.credentials &&
    typeof navigator.credentials.create === 'function' &&
    typeof navigator.credentials.get === 'function'
  );
}

function toU8(buf: BufferSource): Uint8Array {
  if (buf instanceof Uint8Array) return buf;
  if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
  return new Uint8Array((buf as ArrayBufferView).buffer);
}

function extractPrf(cred: PublicKeyCredential | null): Uint8Array | null {
  if (!cred || typeof cred.getClientExtensionResults !== 'function') return null;
  const ext = cred.getClientExtensionResults() as unknown as PrfExtensionOutputs;
  const first = ext?.prf?.results?.first;
  return first ? toU8(first) : null;
}

function rpId(): string | undefined {
  if (typeof window !== 'undefined' && window.location) return window.location.hostname;
  return undefined;
}

/** credentials.create with the PRF extension requested. Returns the new credential. */
async function createPrfCredential(
  fingerprint: string,
  prfSalt: Uint8Array
): Promise<PublicKeyCredential> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge,
    rp: { name: 'svrnty', ...(rpId() ? { id: rpId() } : {}) },
    user: {
      id: new TextEncoder().encode(fingerprint),
      name: fingerprint,
      displayName: 'svrnty identity',
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256
      { type: 'public-key', alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'required',
    },
    timeout: 60_000,
    extensions: { prf: { eval: { first: prfSalt } } } as unknown as AuthenticationExtensionsClientInputs,
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Authenticator did not create a credential');
  return cred;
}

/** credentials.get against a known credentialId, evaluating the PRF. Returns PRF bytes. */
async function assertPrf(credentialId: Uint8Array, prfSalt: Uint8Array): Promise<Uint8Array | null> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge,
    ...(rpId() ? { rpId: rpId() } : {}),
    allowCredentials: [{ type: 'public-key', id: credentialId }],
    userVerification: 'required',
    timeout: 60_000,
    extensions: { prf: { eval: { first: prfSalt } } } as unknown as AuthenticationExtensionsClientInputs,
  };
  const assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  return extractPrf(assertion);
}

function isCancellation(e: unknown): boolean {
  const name = (e as { name?: string })?.name;
  return name === 'NotAllowedError' || name === 'AbortError';
}

// ──────────────────────────────────────────────────────────────────────────
// Session path (invariant #2): the SAME `initSessionKey` passphrase-unlock uses.
// `defaultSessionInit` lazily imports client-store so the claim-gate graph stays
// light (claim-gates re-exports only `isBiometricSeamLive`). There is exactly ONE
// production session path. `__setSessionInitForTest` is a TEST-ONLY seam that
// defaults back to this — it does NOT create a parallel production unlock path.
// ──────────────────────────────────────────────────────────────────────────

async function defaultSessionInit(passphrase: string): Promise<void> {
  const mod = await import('../../lib/identity/client-store');
  await mod.initSessionKey(passphrase);
}

let _sessionInit: (passphrase: string) => Promise<void> = defaultSessionInit;

/** TEST-ONLY: swap the session-establishment fn. Production always uses initSessionKey. */
export function __setSessionInitForTest(fn: (passphrase: string) => Promise<void>): void {
  _sessionInit = fn;
}
/** TEST-ONLY: restore the real initSessionKey-backed session path. */
export function __resetSessionInitForTest(): void {
  _sessionInit = defaultSessionInit;
}

// ──────────────────────────────────────────────────────────────────────────
// The four hooks the glass calls.
// ──────────────────────────────────────────────────────────────────────────

/**
 * Return whether a REAL PRF-backed wrap is enrolled for this fingerprint (invariant #3).
 * Reflects the stored { credentialId, wrappedFactor } — NOT the UI enroll preference.
 */
export async function getBiometricEnrollment(
  fingerprint: string
): Promise<BiometricEnrollmentState> {
  const rec = readWrap(fingerprint);
  if (!rec) return { enrolled: false };
  return {
    enrolled: true,
    credentialIdHint: credentialIdHint(rec.credentialId),
    enrolledAt: rec.enrolledAt,
  };
}

/**
 * Create a WebAuthn platform credential with PRF, derive a wrap-key from the PRF output,
 * WRAP the unlock factor (the passphrase) under it, and store ONLY the wrap. Requires the
 * passphrase so the wrap is sealed while the session is confirmed open (UI gates min length).
 */
export async function enrollBiometric(args: {
  fingerprint: string;
  passphrase: string;
}): Promise<EnrollBiometricResult> {
  const { fingerprint, passphrase } = args;
  if (!webAuthnAvailable()) {
    return {
      ok: false,
      reason: 'unsupported',
      message: 'This device has no WebAuthn platform authenticator.',
    };
  }
  if (!passphrase) {
    return { ok: false, reason: 'wrong-passphrase', message: 'Unlock factor missing.' };
  }
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  try {
    const cred = await createPrfCredential(fingerprint, prfSalt);
    const credentialId = toBase64Url(toU8(cred.rawId));
    // Prefer the create-time PRF output; fall back to a get() for authenticators that
    // only surface PRF on assertion.
    let prfOutput = extractPrf(cred);
    if (!prfOutput) prfOutput = await assertPrf(toU8(cred.rawId), prfSalt);
    if (!prfOutput) {
      return {
        ok: false,
        reason: 'unsupported',
        message: 'Authenticator did not return a PRF output (PRF unsupported).',
      };
    }
    const { hkdfSalt, iv, ciphertext } = await wrapFactor(prfOutput, passphrase);
    // Custody self-check: never persist a wrap we cannot recover with this exact PRF output.
    const recovered = await unwrapFactor(prfOutput, hkdfSalt, iv, ciphertext);
    if (recovered !== passphrase) {
      return { ok: false, reason: 'error', message: 'Wrap self-check failed.' };
    }
    const rec: StoredBiometricWrap = {
      enc_version: WRAP_ENC_VERSION,
      credentialId,
      prfSalt: toBase64(prfSalt),
      hkdfSalt: toBase64(hkdfSalt),
      iv: toBase64(iv),
      wrappedFactor: toBase64(ciphertext),
      enrolledAt: new Date().toISOString(),
    };
    writeWrap(fingerprint, rec);
    return { ok: true, credentialIdHint: credentialIdHint(credentialId) };
  } catch (e) {
    if (isCancellation(e)) return { ok: false, reason: 'cancelled' };
    return { ok: false, reason: 'error', message: (e as Error)?.message ?? String(e) };
  }
}

/**
 * WebAuthn get → re-derive the PRF output → UNWRAP the factor → feed it into the SAME
 * `initSessionKey` path passphrase-unlock uses. No parallel privileged unlock.
 */
export async function unlockWithBiometric(
  fingerprint: string
): Promise<UnlockWithBiometricResult> {
  if (!webAuthnAvailable()) {
    return {
      ok: false,
      reason: 'unsupported',
      message: 'This device has no WebAuthn platform authenticator.',
    };
  }
  const rec = readWrap(fingerprint);
  if (!rec) return { ok: false, reason: 'not-enrolled' };
  try {
    const prfOutput = await assertPrf(fromBase64Url(rec.credentialId), fromBase64(rec.prfSalt));
    if (!prfOutput) {
      return { ok: false, reason: 'error', message: 'Authenticator returned no PRF output.' };
    }
    // Wrong PRF output → AEAD tag fail → throws → caught below. No factor ever leaks.
    const factor = await unwrapFactor(
      prfOutput,
      fromBase64(rec.hkdfSalt),
      fromBase64(rec.iv),
      fromBase64(rec.wrappedFactor)
    );
    await _sessionInit(factor); // ← the ONE session path (initSessionKey)
    return { ok: true };
  } catch (e) {
    if (isCancellation(e)) return { ok: false, reason: 'cancelled' };
    return { ok: false, reason: 'error', message: (e as Error)?.message ?? String(e) };
  }
}

/** Drop the stored { credentialId, wrappedFactor } and the UI preference. */
export async function disableBiometric(
  fingerprint: string
): Promise<DisableBiometricResult> {
  try {
    removeWrap(fingerprint);
    writeEnrollPreference(fingerprint, false);
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: 'error', message: (e as Error)?.message ?? String(e) };
  }
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

/**
 * Claim gate. STILL FALSE: the wrap/unwrap + session-path logic is unit-proven against a
 * mocked authenticator, but a LIVE flip requires a real-device / Playwright PRF proof (an
 * actual platform authenticator returning a stable PRF output). The flip is lockstep with
 * claim-gates.test.ts + biometric-seam.test.ts — a wiring PR flips this constant AND its
 * tests in one change. Do NOT flip on the mock alone.
 */
export function isBiometricSeamLive(): boolean {
  return false;
}
