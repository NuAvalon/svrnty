/**
 * CUR-6 · L5 biometric unlock — fleet seam (WebAuthn-PRF crypto = Flint).
 *
 * WHAT THIS DOES (see shared/outbox/flint/biometric_prf_seam_design.md):
 * The vault session key `_sessionKey` is a NON-EXTRACTABLE PBKDF2(passphrase, 600K) key
 * (client-store.ts). Biometric unlock does NOT bypass it — it RECOVERS the passphrase from a
 * PRF-wrapped local blob, then drives the SAME `initSessionKey(passphrase)` + `loadKey` path a
 * typed passphrase would. Biometric-unlock ≡ passphrase-unlock in security; only the factor to
 * obtain the passphrase differs.
 *
 * HARD INVARIANTS (co-verified by Flint — do NOT weaken):
 *  1. FAIL-CLOSED to passphrase. Every failure (no PRF / cancel / not-enrolled / unwrap-fail /
 *     loadKey-fail / stale-epoch) returns ok:false; the lock screen stays on the passphrase gate.
 *     ok:true is returned ONLY after initSessionKey + loadKey establish a GENUINE session.
 *  2. RECOVERY-TRUTH PRESERVED. Biometric is a CONVENIENCE factor, never a recovery path. The
 *     blob wraps the PASSPHRASE, so it goes STALE on passphrase-change / recovery / re-key — we
 *     stamp `passphrase_epoch` (client-store.getKeyEnvelopeFingerprint) at enroll and INVALIDATE
 *     (delete → force re-enroll) on mismatch. The passphrase + recovery-code paths are untouched.
 *  3. BINDING. wrapKey = HKDF(PRF_output, salt=fingerprint, info) and unlock pins
 *     allowCredentials:[credentialId] — no cross-identity/credential reuse.
 *  4. WRAP MATERIAL LOCAL-ONLY. The wrapped blob lives in a local IndexedDB (svrnty-biometric);
 *     the PRF secret never leaves the authenticator; nothing is sent to any server.
 *  5. NO DECORATIVE STATE. isBiometricSeamLive() STAYS false until this is wired + real-device +
 *     co-verified in a SEPARATE change (do NOT flip it here).
 *
 * The UI glass still never derives keys or stores wrap material itself — it calls this seam only.
 */

// Session/vault integration — the EXISTING passphrase-unlock primitives (client-store.ts).
// We ADD alongside them; we never modify the passphrase or recovery/restore control flow.
// Relative (not '@/…') so the node:test path resolves under `tsx --test`.
import {
  initSessionKey,
  loadKey,
  lockSession,
  isSessionUnlocked,
  hasEncryptedKeys,
  getKeyEnvelopeFingerprint,
  verifyPassphrase,
} from '../../lib/identity/client-store';

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

// ─────────────────────────────────────────────────────────────────────────────
// PRF-wrap crypto + local blob storage (Flint). All of this is CONVENIENCE-layer
// crypto around the EXISTING vault: it only ever reconstructs the passphrase and
// hands it to the untouched initSessionKey/loadKey path. It never derives, holds,
// or exports the vault key itself.
// ─────────────────────────────────────────────────────────────────────────────

/** Local IndexedDB for wrapped blobs — SEPARATE from the vault DB so a not-yet-live
 *  convenience feature triggers no schema migration on the identity/keys database. */
const BIOMETRIC_DB_NAME = 'svrnty-biometric';
const BIOMETRIC_DB_VERSION = 1;
const BIOMETRIC_STORE = 'wrapped_blobs';
/** Wrapped-blob record schema version (bump if the record shape changes). */
const BIOMETRIC_ENC_VERSION = 1;
/** HKDF info label — domain-separates this wrap from any other PRF use. v0 = wrap format. */
const HKDF_INFO = 'svrnty:biometric-wrap:v0';
const PRF_SALT_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const CHALLENGE_BYTES = 32;
const WEBAUTHN_TIMEOUT_MS = 60_000;

/** The wrapped-passphrase blob, one per fingerprint, in svrnty-biometric IndexedDB.
 *  `ciphertext` is AES-GCM(HKDF(PRF_output), passphrase) — the PRF secret is NOT here;
 *  without the authenticator this record is inert. All fields are local-only. */
interface WrappedUnlockBlob {
  enc_version: number;
  fingerprint: string;
  /** base64 of the credential rawId; pinned via allowCredentials at unlock (binding). */
  credentialId: string;
  /** base64 PRF eval.first input — reused at unlock so the PRF output reproduces. */
  prf_salt: string;
  /** base64 AES-GCM nonce. */
  iv: string;
  /** base64 AES-GCM ciphertext of the passphrase. */
  ciphertext: string;
  /** client-store.getKeyEnvelopeFingerprint at enroll — stale ⇒ invalidate (recovery-truth). */
  passphrase_epoch: string;
  enrolledAt: string;
}

// ── base64 / buffer helpers (local copies; client-store's are module-private) ──
function u8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToU8(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function toU8(src: BufferSource): Uint8Array {
  if (src instanceof Uint8Array) return src;
  if (src instanceof ArrayBuffer) return new Uint8Array(src);
  const v = src as ArrayBufferView;
  return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
}

/** Short, NON-secret UI hint (never a key) — trailing tail of the credentialId base64. */
function hintFromCredentialId(credentialIdB64: string): string {
  return '…' + credentialIdB64.slice(-8);
}
function hintFromFingerprint(fingerprint: string): string {
  return fingerprint.slice(-8);
}

// ── local blob storage (own IndexedDB; guarded for non-browser / SSR / node:test) ──
function bioStorageAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

function openBioDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(BIOMETRIC_DB_NAME, BIOMETRIC_DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(BIOMETRIC_STORE)) {
        db.createObjectStore(BIOMETRIC_STORE, { keyPath: 'fingerprint' });
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onerror = () => reject(request.error);
    request.onblocked = () =>
      reject(new Error('svrnty-biometric database is upgrading — close other tabs and reload'));
  });
}

async function bioGet(fingerprint: string): Promise<WrappedUnlockBlob | null> {
  const db = await openBioDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(BIOMETRIC_STORE, 'readonly');
    const req = tx.objectStore(BIOMETRIC_STORE).get(fingerprint);
    req.onsuccess = () => resolve((req.result as WrappedUnlockBlob) ?? null);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

async function bioPut(blob: WrappedUnlockBlob): Promise<void> {
  const db = await openBioDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(BIOMETRIC_STORE, 'readwrite');
    tx.objectStore(BIOMETRIC_STORE).put(blob);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function bioDelete(fingerprint: string): Promise<void> {
  const db = await openBioDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(BIOMETRIC_STORE, 'readwrite');
    tx.objectStore(BIOMETRIC_STORE).delete(fingerprint);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

/** Best-effort invalidation on a failure path — never throws (fail-closed hygiene). */
async function safeBioDelete(fingerprint: string): Promise<void> {
  try {
    if (bioStorageAvailable()) await bioDelete(fingerprint);
  } catch {
    /* invalidation is best-effort; the fail-closed loadKey check still protects unlock */
  }
}

// ── WebAuthn + PRF ─────────────────────────────────────────────────────────────
function webauthnAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    !!navigator.credentials &&
    typeof navigator.credentials.create === 'function' &&
    typeof navigator.credentials.get === 'function' &&
    typeof PublicKeyCredential !== 'undefined'
  );
}

/** Pull the PRF eval.first output from a credential/assertion, or null if absent. */
function extractPrfFirst(cred: PublicKeyCredential): Uint8Array | null {
  const ext = cred.getClientExtensionResults();
  const first = ext?.prf?.results?.first;
  return first ? toU8(first) : null;
}

/** Did the authenticator explicitly report PRF unsupported (enabled === false)? */
function prfExplicitlyDisabled(cred: PublicKeyCredential): boolean {
  return cred.getClientExtensionResults()?.prf?.enabled === false;
}

async function createPrfCredential(
  fingerprint: string,
  prfSalt: Uint8Array,
): Promise<PublicKeyCredential> {
  // Opaque ≤64-byte user handle bound to the fingerprint (not the fingerprint verbatim,
  // which may exceed 64 bytes). Non-secret.
  const userId = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(fingerprint)),
  );
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES)),
    // Local-first: rp.id defaults to the current origin's effective domain (no server RP).
    rp: { name: 'svrnty' },
    user: { id: userId, name: `svrnty:${hintFromFingerprint(fingerprint)}`, displayName: 'svrnty device unlock' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256
      { type: 'public-key', alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'required',
      userVerification: 'required',
    },
    timeout: WEBAUTHN_TIMEOUT_MS,
    // Local-only: we never verify attestation server-side (we consume only the PRF output).
    attestation: 'none',
    extensions: { prf: { eval: { first: prfSalt } } },
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new DOMException('No credential created', 'NotAllowedError');
  return cred;
}

async function getPrfAssertion(
  credentialId: Uint8Array,
  prfSalt: Uint8Array,
): Promise<PublicKeyCredential> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES)),
    allowCredentials: [{ type: 'public-key', id: credentialId }],
    userVerification: 'required',
    timeout: WEBAUTHN_TIMEOUT_MS,
    extensions: { prf: { eval: { first: prfSalt } } },
  };
  const assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!assertion) throw new DOMException('No assertion', 'NotAllowedError');
  return assertion;
}

/** Map a WebAuthn ceremony throw → user-cancel vs generic error (fail-closed either way). */
function isUserCancel(e: unknown): boolean {
  return e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError');
}

/** wrapKey = HKDF-SHA256(PRF_output, salt=fingerprint, info) → non-extractable AES-GCM-256.
 *  salt=fingerprint binds the wrap to this identity (invariant 3). */
async function deriveWrapKey(prfOutput: Uint8Array, fingerprint: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(fingerprint),
      info: new TextEncoder().encode(HKDF_INFO),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  );
}

/**
 * Fleet: return whether a PRF-backed credential is enrolled for this fingerprint.
 * Reflects REAL wrapped-blob presence in local IndexedDB (invariant 4) — NOT the UI-intent
 * preference. No blob ⇒ not enrolled.
 */
export async function getBiometricEnrollment(
  fingerprint: string
): Promise<BiometricEnrollmentState> {
  if (!bioStorageAvailable()) return { enrolled: false };
  try {
    const blob = await bioGet(fingerprint);
    if (!blob) return { enrolled: false };
    return {
      enrolled: true,
      credentialIdHint: hintFromCredentialId(blob.credentialId),
      enrolledAt: blob.enrolledAt,
    };
  } catch {
    return { enrolled: false };
  }
}

/**
 * Fleet: create a platform WebAuthn credential with the PRF extension, then AES-GCM-wrap the
 * (validated) passphrase under HKDF(PRF_output). Called from Settings while the session is OPEN.
 *
 * Order (design §Flow ENROLL):
 *  1. Cheap capability guard (no prompt) — unsupported env falls back to passphrase.
 *  2. Session must be OPEN (isSessionUnlocked); never call initSessionKey here (that would
 *     overwrite the good session key with a wrong one on a mismatch).
 *  3. Require encrypted-at-rest keys so passphrase_epoch is a real envelope fingerprint AND the
 *     passphrase has a crypto gate to verify against (a legacy plaintext vault can't back a
 *     device-unlock).
 *  4. Verify the TYPED passphrase against the at-rest record's PBKDF2→AES-GCM gate
 *     (verifyPassphrase, non-destructive) — NOT against the plaintext loadKey().passphrase
 *     field, which can diverge from the live unlock passphrase. Never wrap an unverified one.
 *  5. credentials.create with PRF; obtain the PRF output (falling back to a follow-up get() on
 *     authenticators that only surface PRF results on assertion). No PRF ⇒ 'unsupported'.
 *  6. HKDF → AES-GCM wrap the passphrase; persist the blob locally (per fingerprint).
 */
export async function enrollBiometric(args: {
  fingerprint: string;
  passphrase: string;
}): Promise<EnrollBiometricResult> {
  const { fingerprint, passphrase } = args;

  // 1. Capability guard — cheap feature-detect, no ceremony/prompt.
  if (!webauthnAvailable() || !bioStorageAvailable()) {
    return {
      ok: false,
      reason: 'unsupported',
      message: 'Device unlock is not supported here — your passphrase remains your unlock.',
    };
  }

  // 2. Session must be OPEN — device-unlock wraps the live vault passphrase for later replay.
  if (!isSessionUnlocked()) {
    return {
      ok: false,
      reason: 'error',
      message: 'Unlock your vault first, then enable device unlock.',
    };
  }

  // 3. Require encrypted-at-rest keys (F1 norm): epoch is a real envelope fingerprint AND the
  //    passphrase can be verified against the at-rest crypto gate in step 4.
  const epoch = (await hasEncryptedKeys(fingerprint))
    ? await getKeyEnvelopeFingerprint(fingerprint)
    : null;
  if (!epoch) {
    return {
      ok: false,
      reason: 'error',
      message: 'Device unlock needs encrypted-at-rest keys on this identity.',
    };
  }

  // 4. Verify the TYPED passphrase against the at-rest key record's crypto gate — the same
  //    PBKDF2→AES-GCM that guards unlock, run non-destructively (never touches the live session
  //    key). We wrap the typed passphrase below, so it MUST be the real vault passphrase. We do
  //    NOT compare against loadKey().passphrase: that plaintext field can diverge from the live
  //    unlock passphrase (restore/import store '', a passphrase change re-keys the record without
  //    rewriting the field) — the false 'wrong-passphrase' the enroll smoke caught.
  if (!(await verifyPassphrase(fingerprint, passphrase))) {
    return { ok: false, reason: 'wrong-passphrase' };
  }

  // 5. WebAuthn create + PRF output.
  const prfSalt = crypto.getRandomValues(new Uint8Array(PRF_SALT_BYTES));
  let cred: PublicKeyCredential;
  try {
    cred = await createPrfCredential(fingerprint, prfSalt);
  } catch (e) {
    return isUserCancel(e)
      ? { ok: false, reason: 'cancelled' }
      : { ok: false, reason: 'error', message: 'Could not create the device credential.' };
  }

  let prfOutput = extractPrfFirst(cred);
  if (!prfOutput) {
    // Many platforms only surface PRF results on an assertion, not at creation. If the
    // authenticator didn't explicitly say PRF is unsupported, try one get() to obtain it —
    // this also proves the enroll→unlock round-trip before we store anything.
    if (!prfExplicitlyDisabled(cred)) {
      try {
        const assertion = await getPrfAssertion(toU8(cred.rawId), prfSalt);
        prfOutput = extractPrfFirst(assertion);
      } catch {
        prfOutput = null;
      }
    }
  }
  if (!prfOutput) {
    return {
      ok: false,
      reason: 'unsupported',
      message: 'This device authenticator does not support PRF — your passphrase remains your unlock.',
    };
  }

  // 6. HKDF → AES-GCM wrap the passphrase, persist locally.
  try {
    const wrapKey = await deriveWrapKey(prfOutput, fingerprint);
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        wrapKey,
        new TextEncoder().encode(passphrase),
      ),
    );
    const credentialId = u8ToBase64(toU8(cred.rawId));
    const blob: WrappedUnlockBlob = {
      enc_version: BIOMETRIC_ENC_VERSION,
      fingerprint,
      credentialId,
      prf_salt: u8ToBase64(prfSalt),
      iv: u8ToBase64(iv),
      ciphertext: u8ToBase64(ciphertext),
      passphrase_epoch: epoch,
      enrolledAt: new Date().toISOString(),
    };
    await bioPut(blob);
    return { ok: true, credentialIdHint: hintFromCredentialId(credentialId) };
  } catch {
    return { ok: false, reason: 'error', message: 'Could not seal the device-unlock data.' };
  }
}

/**
 * Fleet: from the lock screen, WebAuthn get + PRF unwrap → the passphrase → the EXISTING
 * initSessionKey/loadKey session. Returns ok:true ONLY after a genuine session is established
 * (invariant 1). Every failure returns ok:false and leaves the passphrase gate in place — this
 * NEVER bypasses the passphrase, it only recovers it.
 *
 * Order (design §Flow UNLOCK):
 *  1. Load the local blob (none → not-enrolled).
 *  2. Epoch check — a passphrase-change / recovery / re-key rewrote the keys record, so a stale
 *     blob is INVALIDATED (deleted) here and the user falls back to passphrase (invariant 2).
 *  3. WebAuthn get (allowCredentials pinned → binding) → PRF output.
 *  4. HKDF → AES-GCM decrypt → passphrase (auth-tag fail → error).
 *  5. initSessionKey(passphrase) then loadKey MUST succeed → genuine session. On any failure:
 *     lockSession() (no half-open session) and ok:false. NO bypass.
 */
export async function unlockWithBiometric(
  fingerprint: string
): Promise<UnlockWithBiometricResult> {
  // 1. Local blob.
  if (!bioStorageAvailable()) return { ok: false, reason: 'not-enrolled' };
  let blob: WrappedUnlockBlob | null;
  try {
    blob = await bioGet(fingerprint);
  } catch {
    return { ok: false, reason: 'error' };
  }
  if (!blob) return { ok: false, reason: 'not-enrolled' };

  // 2. Recovery-truth: invalidate a stale wrapped passphrase (epoch mismatch) → re-enroll.
  let epoch: string | null = null;
  try {
    epoch = await getKeyEnvelopeFingerprint(fingerprint);
  } catch {
    epoch = null;
  }
  if (!epoch || epoch !== blob.passphrase_epoch) {
    await safeBioDelete(fingerprint);
    return {
      ok: false,
      reason: 'error',
      message: 'Your passphrase changed — set up device unlock again. Enter your passphrase to unlock.',
    };
  }

  if (!webauthnAvailable()) return { ok: false, reason: 'error' };

  // 3. WebAuthn assertion + PRF output (credential pinned via allowCredentials → binding).
  let assertion: PublicKeyCredential;
  try {
    assertion = await getPrfAssertion(base64ToU8(blob.credentialId), base64ToU8(blob.prf_salt));
  } catch (e) {
    return isUserCancel(e)
      ? { ok: false, reason: 'cancelled' }
      : { ok: false, reason: 'error' };
  }
  const prfOutput = extractPrfFirst(assertion);
  if (!prfOutput) return { ok: false, reason: 'error' };

  // 4. Unwrap the passphrase (auth-tag failure → fall to passphrase).
  let passphrase: string;
  try {
    const wrapKey = await deriveWrapKey(prfOutput, fingerprint);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToU8(blob.iv) },
      wrapKey,
      base64ToU8(blob.ciphertext),
    );
    passphrase = new TextDecoder().decode(plaintext);
  } catch {
    return { ok: false, reason: 'error' };
  }

  // 5. Establish + VERIFY a genuine session — this is the ONLY thing that authorizes ok:true.
  try {
    await initSessionKey(passphrase);
    const key = await loadKey(fingerprint); // throws on wrong passphrase; null if no key record
    if (!key) {
      lockSession();
      return { ok: false, reason: 'error' };
    }
  } catch {
    // Unwrapped passphrase no longer opens the vault (epoch missed a change / corruption):
    // clear the half-open session and invalidate the now-useless blob. Fail closed.
    lockSession();
    await safeBioDelete(fingerprint);
    return { ok: false, reason: 'error' };
  }

  return { ok: true };
}

/**
 * Fleet: disable device unlock — remove the wrapped blob (the wrap material) and clear the
 * UI preference. Without the blob the platform credential is inert for unlock (nothing to
 * recover the passphrase from), which fully disables biometric unlock.
 *
 * NOTE: WebAuthn exposes no API to programmatically delete a platform credential; the credential
 * itself remains in the OS authenticator until the user removes it via device settings. Deleting
 * the local blob is the security-relevant step. Idempotent (no blob → still ok).
 */
export async function disableBiometric(
  fingerprint: string
): Promise<DisableBiometricResult> {
  writeEnrollPreference(fingerprint, false);
  if (!bioStorageAvailable()) return { ok: true };
  try {
    await bioDelete(fingerprint);
    return { ok: true };
  } catch {
    return { ok: false, reason: 'error', message: 'Could not remove the device-unlock data.' };
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
 * Default FALSE (invariant 5 — prod stays honest). The enroll/unlock/disable bodies ARE wired;
 * going live is PER-ENVIRONMENT via NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE (inlined at build time).
 * Set it to 'true' ONLY in a build that has passed Flint's crypto co-verify + Athena's
 * real-device WebAuthn-PRF test (e.g. the dev-test build). Unset / anything but 'true' → false,
 * so prod is honest automatically even post-merge — never decorative-live ahead of verification
 * (claim-honesty). Strict === 'true' (no truthy coercion).
 */
export function isBiometricSeamLive(): boolean {
  return process.env.NEXT_PUBLIC_BIOMETRIC_SEAM_LIVE === 'true';
}
