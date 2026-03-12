// src/lib/trust/signals.ts
// Trust signal creation, signing, and verification.
// Signals are signed JSON blobs — channel-agnostic (email, Signal, QR, direct).

import type { TrustSignal, SignedSignal } from './types';
import { hybridSign, hybridVerify } from '@/lib/crypto/hybrid';
import { createMessage, readPrivateKey, decryptKey, sign as pgpSign } from 'openpgp';

/**
 * Create and sign a trust signal.
 * Supports both hybrid (v2) and classical-only (v1) signing.
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

  if (pqSigningSecretKey) {
    // v2: hybrid dual signature (classical + PQ)
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

  // v1: classical-only signature
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
  // Break signals always reach trusted contacts
  if (signal.type === 'break' && isRecipientTrusted) {
    return true;
  }

  // Other signals require trusted sender → trusted recipient
  return isSenderTrusted && isRecipientTrusted;
}

/**
 * Introduction creates a known contact, not a trusted one.
 * Trust must be explicitly granted by the person.
 */
export function introductionCreatesTrust(): boolean {
  return false; // introductions make you known, never trusted
}
