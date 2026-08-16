// src/lib/trust/signals.ts
// Trust signal creation, signing, and verification.
// Signals are signed JSON blobs — channel-agnostic (email, Signal, QR, direct).
//
// Binding (security punchlist 2026-08-16): `from` is inside the signed payload.
// Replay: reject timestamps older than SIGNAL_MAX_AGE_MS (default 7 days).

import type { TrustSignal, SignedSignal } from './types';
import { hybridVerify } from '../crypto/hybrid';
import {
  signWithEnvelope,
  verifyWithEnvelope,
  classicalSignatureBinds,
  type EnvelopeSignature,
} from '../crypto/sign-envelope';
import { canonicalize } from '../format/canonical';
import { DOMAIN_TRUST_SIGNAL } from '../format/envelope';

/** Default freshness window for received signals (7 days). */
export const SIGNAL_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * LEGACY signed bytes (pre-0.1): raw JSON.stringify — order-dependent, NFC-blind. Retained ONLY to
 * verify signatures made before the 0.1 envelope landed, inside the freshness window. Never sign
 * with this. See the sunset note in verifySignal.
 */
function canonicalSignPayload(
  payload: TrustSignal,
  from: string,
  to: string,
  timestamp: string
): string {
  return JSON.stringify({ payload, from, to, timestamp });
}

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

  const envSig: EnvelopeSignature = signal.pq_signature
    ? { classical: signal.signature, pq_signature: signal.pq_signature }
    : { classical: signal.signature };

  // PRIMARY (0.1): domain-separated, suite-bound envelope over canonical bytes.
  const canonicalInput = trustSignalCanonicalInput(
    signal.payload,
    signal.from,
    signal.to,
    signal.timestamp
  );
  if (
    await verifyWithEnvelope(
      DOMAIN_TRUST_SIGNAL,
      canonicalInput,
      envSig,
      senderPublicKey,
      senderPqSigPublicKey
    )
  ) {
    return true;
  }

  // LEGACY verify paths (raw JSON.stringify, pre-0.1). SELF-SUNSETTING: the freshness window above
  // (SIGNAL_MAX_AGE_MS = 7 days) means ~7 days after this deploys, every still-fresh signal was
  // signed with the 0.1 envelope — DELETE this whole block then (≈2026-08-23 if deployed
  // 2026-08-16). Do NOT re-canonicalize these: legacy signers signed the exact bytes below. KB#85978.
  const hybridSig = signal.pq_signature
    ? {
        classical: signal.signature,
        post_quantum: signal.pq_signature,
        algorithm: 'ED25519+ML-DSA-87' as const,
      }
    : { classical: signal.signature };
  const acceptClassicalOnly = !signal.pq_signature;
  const legacyCandidates = [
    // L1: punchlist binding (from included) — the immediate 0.1 predecessor.
    canonicalSignPayload(signal.payload, signal.from, signal.to, signal.timestamp),
    // L2: pre-punchlist (from UNSIGNED) — classical-only, never accepted for hybrid signals.
    JSON.stringify({ payload: signal.payload, to: signal.to, timestamp: signal.timestamp }),
  ];
  for (let i = 0; i < legacyCandidates.length; i++) {
    // L2 (from unsigned) is never accepted for hybrid (v2) signals — those must bind from.
    if (i === 1 && signal.pq_signature) continue;
    // Bind the embedded message to this candidate: hybridVerify alone confirms only that the inline
    // classical signature is internally valid, not that it signs THIS candidate (see
    // classicalSignatureBinds). Also hardens the legacy window against field substitution.
    if (!(await classicalSignatureBinds(signal.signature, legacyCandidates[i]))) continue;
    const ok = await hybridVerify(
      legacyCandidates[i],
      hybridSig,
      senderPublicKey,
      senderPqSigPublicKey,
      acceptClassicalOnly
    );
    if (ok) return true;
  }

  return false;
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
