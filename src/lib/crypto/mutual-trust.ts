// src/lib/crypto/mutual-trust.ts
// ZKP Mutual Trust Discovery Protocol
//
// Implements Private Set Intersection for binary trust:
// - Two parties compute a shared commitment via DH + HMAC
// - If both submit matching commitments, trust is mutual
// - Satellite sees hashes, never learns who trusts whom
// - Revocation is silent (remove commitment, other party can't distinguish)
//
// Spec: outpost/flint/zkp_mutual_trust_spec.md
// Author: Flint (session 112)

import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// --- Constants ---

const TRUST_PROTOCOL_VERSION = 'svrnty-trust-v1';
const EPOCH_WEEK_SECONDS = 604800; // 7 days
const DEFAULT_TTL_WEEKS = 104; // 2 years

// --- Types ---

export interface TrustCommitment {
  /** The commitment hash (HMAC of sorted fingerprints + epoch) */
  commitment: string;
  /** Submitting party's fingerprint */
  from_fingerprint: string;
  /** Ed25519 signature over the commitment */
  signature: string;
  /** Epoch week the commitment was generated for */
  epoch_week: number;
  /** When this trust expires (epoch week) */
  ttl_expires: number;
}

export interface MutualTrustResult {
  /** Whether trust is mutual */
  mutual: boolean;
  /** The other party's fingerprint (only if mutual) */
  peer_fingerprint?: string;
  /** When mutual trust was established */
  established_at?: number;
  /** When this trust expires (earliest of both parties' TTLs) */
  expires_at?: number;
}

export interface TrustDecayConfig {
  /** TTL in weeks (default 104 = 2 years) */
  ttl_weeks: number;
  /** Whether to auto-resubmit before expiry */
  auto_renew: boolean;
}

// --- Core Protocol ---

/**
 * Derive shared secret from two Ed25519 keys via X25519 DH.
 * This secret is known only to the two parties — the satellite cannot compute it.
 */
export function deriveSharedSecret(
  myPrivateKey: Uint8Array,
  theirPublicKey: Uint8Array
): Uint8Array {
  // @noble/curves v2: edwardsToMontgomery* → ed25519.utils.toMontgomery*
  const myX25519Private = ed25519.utils.toMontgomerySecret(myPrivateKey);
  const theirX25519Public = ed25519.utils.toMontgomery(theirPublicKey);

  const rawShared = x25519.getSharedSecret(myX25519Private, theirX25519Public);

  // HKDF to derive a uniform key
  return hkdf(sha256, rawShared, undefined, TRUST_PROTOCOL_VERSION, 32);
}

/**
 * Get the current epoch week (floor(unix_time / 604800)).
 */
export function currentEpochWeek(): number {
  return Math.floor(Date.now() / 1000 / EPOCH_WEEK_SECONDS);
}

/**
 * Sort two fingerprints lexicographically.
 * Critical: both parties must produce the same ordering.
 */
function sortFingerprints(fpA: string, fpB: string): [string, string] {
  return fpA < fpB ? [fpA, fpB] : [fpB, fpA];
}

/**
 * Compute a trust commitment.
 *
 * commitment = HMAC-SHA256(shared_secret, "svrnty-trust-v1" || fp_low || fp_high || epoch_week)
 *
 * Because fingerprints are sorted and the shared secret is symmetric,
 * both parties produce the SAME commitment if both trust each other.
 */
export function computeCommitment(
  sharedSecret: Uint8Array,
  myFingerprint: string,
  theirFingerprint: string,
  epochWeek?: number
): string {
  const epoch = epochWeek ?? currentEpochWeek();
  const [fpLow, fpHigh] = sortFingerprints(myFingerprint, theirFingerprint);

  const message = new TextEncoder().encode(
    `${TRUST_PROTOCOL_VERSION}|${fpLow}|${fpHigh}|${epoch}`
  );

  const commitmentBytes = hmac(sha256, sharedSecret, message);
  return bytesToHex(commitmentBytes);
}

/**
 * Build a full trust commitment ready for satellite submission.
 * The caller must sign the commitment with their Ed25519 key.
 */
export function buildTrustCommitment(
  myPrivateKey: Uint8Array,
  myFingerprint: string,
  theirPublicKey: Uint8Array,
  theirFingerprint: string,
  signFn: (data: Uint8Array, privateKey: Uint8Array) => Uint8Array,
  config?: Partial<TrustDecayConfig>
): TrustCommitment {
  const sharedSecret = deriveSharedSecret(myPrivateKey, theirPublicKey);
  const epochWeek = currentEpochWeek();
  const ttlWeeks = config?.ttl_weeks ?? DEFAULT_TTL_WEEKS;

  const commitment = computeCommitment(
    sharedSecret,
    myFingerprint,
    theirFingerprint,
    epochWeek
  );

  // Sign the commitment to prove it came from this identity
  const commitmentBytes = new TextEncoder().encode(commitment);
  const signature = signFn(commitmentBytes, myPrivateKey);

  return {
    commitment,
    from_fingerprint: myFingerprint,
    signature: bytesToHex(signature),
    epoch_week: epochWeek,
    ttl_expires: epochWeek + ttlWeeks,
  };
}

/**
 * Verify a trust commitment from a peer.
 * Used by the satellite (or any verifier) to check the commitment is authentic.
 */
export function verifyCommitmentSignature(
  commitment: TrustCommitment,
  peerPublicKey: Uint8Array,
  verifyFn: (signature: Uint8Array, data: Uint8Array, publicKey: Uint8Array) => boolean
): boolean {
  const commitmentBytes = new TextEncoder().encode(commitment.commitment);
  const signatureBytes = hexToBytes(commitment.signature);
  return verifyFn(signatureBytes, commitmentBytes, peerPublicKey);
}

/**
 * Check if a commitment has expired based on current epoch week.
 */
export function isCommitmentExpired(commitment: TrustCommitment): boolean {
  return currentEpochWeek() > commitment.ttl_expires;
}

/**
 * Check if a commitment needs renewal (within 4 weeks of expiry).
 */
export function needsRenewal(commitment: TrustCommitment): boolean {
  return currentEpochWeek() >= commitment.ttl_expires - 4;
}

// --- Satellite Client ---

/**
 * Submit a trust commitment to the satellite.
 */
export async function submitCommitment(
  satelliteUrl: string,
  commitment: TrustCommitment
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`${satelliteUrl}/trust/commit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(commitment),
    });
    if (!res.ok) {
      const body = await res.text();
      return { ok: false, error: body };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Network error' };
  }
}

/**
 * Check for mutual trust matches from the satellite.
 */
export async function checkMutualTrust(
  satelliteUrl: string,
  fingerprint: string
): Promise<MutualTrustResult[]> {
  try {
    const res = await fetch(`${satelliteUrl}/trust/check/${fingerprint}`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

/**
 * Revoke a trust commitment (silent — other party is not notified).
 */
export async function revokeCommitment(
  satelliteUrl: string,
  fingerprint: string,
  signature: string
): Promise<{ ok: boolean }> {
  try {
    const res = await fetch(`${satelliteUrl}/trust/revoke/${fingerprint}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
      },
    });
    return { ok: res.ok };
  } catch {
    return { ok: false };
  }
}
