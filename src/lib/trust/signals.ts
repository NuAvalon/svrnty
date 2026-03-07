// src/lib/trust/signals.ts
// Trust signal creation, signing, and verification.
// Signals are signed JSON blobs — channel-agnostic (email, Signal, QR, direct).

import type { TrustSignal, SignedSignal, TrustLevel } from './types';
import { hybridSign, hybridVerify } from '@/lib/crypto/hybrid';

/**
 * Create and sign a trust signal.
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
  const dataToSign = JSON.stringify({ payload, to, timestamp });

  const signature = await hybridSign(
    dataToSign,
    classicalPrivateKey,
    classicalPassphrase,
    pqSigningSecretKey!
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

/**
 * Verify a received trust signal.
 */
export async function verifySignal(
  signal: SignedSignal,
  senderPublicKey: string,
  senderPqSigPublicKey?: Uint8Array
): Promise<boolean> {
  const dataToVerify = JSON.stringify({
    payload: signal.payload,
    to: signal.to,
    timestamp: signal.timestamp,
  });

  const hybridSig = signal.pq_signature
    ? {
        classical: signal.signature,
        post_quantum: signal.pq_signature,
        algorithm: 'ED25519+ML-DSA-65' as const,
      }
    : { classical: signal.signature };

  return hybridVerify(
    dataToVerify,
    hybridSig,
    senderPublicKey,
    senderPqSigPublicKey,
    !signal.pq_signature // accept classical-only for v1 peers
  );
}

// --- Signal factories (convenience) ---

export function vouchSignal(subject: string, level: TrustLevel): TrustSignal {
  return { type: 'vouch', subject, level };
}

export function concernSignal(subject: string, detail: string): TrustSignal {
  return { type: 'concern', subject, detail };
}

export function breakSignal(subject: string, severity: 'soft' | 'hard'): TrustSignal {
  return { type: 'break', subject, severity };
}

export function syncSignal(myLevel: TrustLevel): TrustSignal {
  return { type: 'sync', my_level: myLevel };
}

export function introduceSignal(subject: string, pubKey: string, name: string): TrustSignal {
  return { type: 'introduce', subject, pub_key: pubKey, name };
}

export function keyRotationSignal(oldFingerprint: string, newFingerprint: string): TrustSignal {
  return { type: 'key_rotation', old_fingerprint: oldFingerprint, new_fingerprint: newFingerprint };
}

// --- Signal propagation rules ---

/**
 * Should this signal be propagated to a contact at the given level?
 * Rule 1: signals from L3+ propagate. L1 signals suppressed.
 * Rule 2: break signals always propagate to L2+.
 */
export function shouldPropagate(
  signal: TrustSignal,
  senderLevelForMe: TrustLevel,
  recipientLevel: TrustLevel
): boolean {
  // Break signals always reach L2+
  if (signal.type === 'break' && recipientLevel >= 2) {
    return true;
  }

  // Other signals require sender at L3+
  if (senderLevelForMe < 3) {
    return false;
  }

  // Propagate to L2+ contacts
  return recipientLevel >= 2;
}

/**
 * Max trust level through introduction.
 * Rule 3: min(introducer's level, introduced's level) - 1
 */
export function maxIntroductionLevel(
  introducerLevel: TrustLevel,
  introducedLevel: TrustLevel
): TrustLevel {
  return Math.max(0, Math.min(introducerLevel, introducedLevel) - 1) as TrustLevel;
}
