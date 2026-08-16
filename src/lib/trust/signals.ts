// src/lib/trust/signals.ts
// Trust signal creation, signing, and verification.
// Signals are signed JSON blobs — channel-agnostic (email, Signal, QR, direct).
//
// Binding (security punchlist 2026-08-16): `from` is inside the signed payload.
// Replay: reject timestamps older than SIGNAL_MAX_AGE_MS (default 7 days).

import type { TrustSignal, SignedSignal } from './types';
import { hybridSign, hybridVerify } from '@/lib/crypto/hybrid';
import { createMessage, readPrivateKey, decryptKey, sign as pgpSign } from 'openpgp';

/** Default freshness window for received signals (7 days). */
export const SIGNAL_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** Canonical bytes that are dual-signed. Order is load-bearing — do not reorder keys. */
function canonicalSignPayload(
  payload: TrustSignal,
  from: string,
  to: string,
  timestamp: string
): string {
  return JSON.stringify({ payload, from, to, timestamp });
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
  const dataToSign = canonicalSignPayload(payload, from, to, timestamp);

  if (pqSigningSecretKey) {
    const signature = await hybridSign(
      dataToSign,
      classicalPrivateKey,
      classicalPassphrase,
      pqSigningSecretKey
    );

    return {
      payload,
      from,
      to,
      timestamp,
      signature: signature.classical,
      pq_signature: signature.post_quantum,
    };
  }

  const privateKeyObj = await readPrivateKey({ armoredKey: classicalPrivateKey });
  const decryptedKey = await decryptKey({
    privateKey: privateKeyObj,
    passphrase: classicalPassphrase,
  });
  const message = await createMessage({ text: dataToSign });
  const classicalSig = await pgpSign({ message, signingKeys: decryptedKey });

  return {
    payload,
    from,
    to,
    timestamp,
    signature: classicalSig.toString(),
  };
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

  // Prefer new binding (includes from). Accept legacy payloads that omitted from
  // only when classical-only and within the freshness window — still reject if
  // the claimed `from` cannot be verified under either encoding.
  const candidates = [
    canonicalSignPayload(signal.payload, signal.from, signal.to, signal.timestamp),
    // Legacy (pre-punchlist): from was unsigned
    JSON.stringify({
      payload: signal.payload,
      to: signal.to,
      timestamp: signal.timestamp,
    }),
  ];

  const hybridSig = signal.pq_signature
    ? {
        classical: signal.signature,
        post_quantum: signal.pq_signature,
        algorithm: 'ED25519+ML-DSA-87' as const,
      }
    : { classical: signal.signature };

  for (let i = 0; i < candidates.length; i++) {
    const acceptClassicalOnly = !signal.pq_signature;
    // Do not accept legacy encoding for hybrid (v2) signals — those must bind from.
    if (i === 1 && signal.pq_signature) continue;

    const ok = await hybridVerify(
      candidates[i],
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
