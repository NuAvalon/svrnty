// src/lib/trust/signals.ts
// Trust signal creation, signing, and verification.
// Signals are signed JSON blobs — channel-agnostic (email, Signal, QR, direct).
//
// Binding (security punchlist 2026-08-16): `from` is inside the signed payload.
// Replay: reject timestamps older than SIGNAL_MAX_AGE_MS (default 7 days).

import type { TrustSignal, SignedSignal } from './types';
import { signWithEnvelope, verifyWithEnvelope, envelopeSignatureOf, isAbsentOrWellFormedPq } from '../crypto/sign-envelope';
import { canonicalize } from '../format/canonical';
import { DOMAIN_TRUST_SIGNAL } from '../format/envelope';

/** Default freshness window for received signals (7 days). */
export const SIGNAL_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** Canonical signing input for a 0.1 trust-signal envelope (NFC-safe, key-order-independent). */
function trustSignalCanonicalInput(
  payload: TrustSignal,
  from: string,
  to: string,
  timestamp: string
): string {
  return canonicalize({ payload, from, to, timestamp });
}

/**
 * Create and sign a trust signal.
 * Supports both hybrid (v2) and classical-only (v1) signing.
 * `from` is always included in the signed material (attribution binding).
 */
export async function createSignal(
  payload: TrustSignal,
  from: string,
  to: string,
  classicalPrivateKey: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array
): Promise<SignedSignal> {
  const timestamp = new Date().toISOString();
  const canonicalInput = trustSignalCanonicalInput(payload, from, to, timestamp);

  // 0.1 envelope: sign( LP(DOMAIN_TRUST_SIGNAL) ‖ LP(suite_id) ‖ canonicalInput ). Suite (and the
  // choice of hybrid vs classical) is handled inside signWithEnvelope from pqSigningSecretKey.
  const sig = await signWithEnvelope(
    DOMAIN_TRUST_SIGNAL,
    canonicalInput,
    classicalPrivateKey,
    classicalPassphrase,
    pqSigningSecretKey
  );

  const signed: SignedSignal = { payload, from, to, timestamp, signature: sig.classical };
  if (sig.pq_signature) signed.pq_signature = sig.pq_signature;
  return signed;
}

/**
 * Verify a received trust signal.
 * Checks signature binding (including `from`) and timestamp freshness.
 */
export async function verifySignal(
  signal: SignedSignal,
  senderPublicKey: string,
  senderPqSigPublicKey?: Uint8Array,
  options?: { maxAgeMs?: number; nowMs?: number }
): Promise<boolean> {
  const maxAgeMs = options?.maxAgeMs ?? SIGNAL_MAX_AGE_MS;
  const nowMs = options?.nowMs ?? Date.now();
  const ts = Date.parse(signal.timestamp);
  if (!Number.isFinite(ts) || Math.abs(nowMs - ts) > maxAgeMs) {
    return false;
  }

  // A malformed pq_signature ('' / null / non-string) refuses: it is never "no PQ half" (#717).
  if (!isAbsentOrWellFormedPq(signal.pq_signature)) return false;

  // The 0.1 envelope is the ONLY accepted form: domain-separated, suite-bound, over canonical bytes. The pre-0.1
  // raw-JSON legacy verify loop was deleted (#718): it sunset ~2026-08-23 (7-day freshness window), nothing emits
  // it, and it was the only path into hybridVerify's classical-only branch outside verifyWithEnvelope.
  return verifyWithEnvelope(
    DOMAIN_TRUST_SIGNAL,
    trustSignalCanonicalInput(signal.payload, signal.from, signal.to, signal.timestamp),
    envelopeSignatureOf(signal.signature, signal.pq_signature),
    senderPublicKey,
    senderPqSigPublicKey
  );
}

// --- Signal factories ---

export function vouchSignal(subject: string): TrustSignal {
  return { type: 'vouch', subject };
}

export function concernSignal(subject: string, detail: string): TrustSignal {
  return { type: 'concern', subject, detail };
}

export function breakSignal(subject: string, reason?: string): TrustSignal {
  return { type: 'break', subject, reason };
}

export function syncSignal(trusted: boolean): TrustSignal {
  return { type: 'sync', trusted };
}

export function introduceSignal(subject: string, pubKey: string, name: string): TrustSignal {
  return { type: 'introduce', subject, pub_key: pubKey, name };
}

export function keyRotationSignal(oldFingerprint: string, newFingerprint: string): TrustSignal {
  return { type: 'key_rotation', old_fingerprint: oldFingerprint, new_fingerprint: newFingerprint };
}

// --- Signal propagation rules ---

/**
 * Should this signal be propagated to a contact?
 * Break signals always propagate to trusted contacts.
 * Other signals propagate from trusted senders to trusted contacts.
 */
export function shouldPropagate(
  signal: TrustSignal,
  isSenderTrusted: boolean,
  isRecipientTrusted: boolean
): boolean {
  if (signal.type === 'break' && isRecipientTrusted) {
    return true;
  }
  return isSenderTrusted && isRecipientTrusted;
}

/**
 * Introduction creates a known contact, not a trusted one.
 * Trust must be explicitly granted by the person.
 */
export function introductionCreatesTrust(): boolean {
  return false;
}
