// src/lib/trust/mutual-trust-sync.ts
// PSI-based mutual trust discovery — client-side orchestrator.
//
// Implements the DH-PSI protocol against satellite endpoints.
// Satellite never learns who trusts whom — it only relays blinded sets.
// Client computes intersection locally, persists via deps.applyMutualResult() (storage-agnostic).
//
// Protocol (5-step DH-PSI):
//   1. Alice blinds her trusted fingerprints, sends to satellite → session_id
//   2. Bob checks pending sessions, fetches Alice's blinded set
//   3. Bob re-blinds Alice's set with his key, blinds his own set, responds
//   4. Alice fetches result: Bob's blinded set + her re-blinded set
//   5. Alice re-blinds Bob's set, computes intersection locally
//
// Crypto: X25519 point hashing + ECDH blinding (DH commutativity).
// Both parties end up with doubly-blinded sets — intersection = mutual contacts.
//
// Spec: zkp_mutual_trust_spec.md
// Satellite endpoints: /trust/psi/* (infra/satellite/satellite.py)
// Crypto primitives: infra/satellite/crypto_utils.py (reference impl)

import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

// --- Constants ---

const PSI_SALT = 'svrnty-psi-v1';
const PSI_POINT_INFO = 'svrnty-psi-point-derivation';
const PSI_SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour — matches satellite expiry

// --- Types ---

export interface PSIKeypair {
  /** Ephemeral X25519 private key (base64) — single-use per session */
  privateKey: string;
  /** Ephemeral X25519 public key (base64) — not sent to satellite */
  publicKey: string;
}

export interface PSISyncResult {
  /** Peer fingerprint(s) flagged as sharing >=1 trusted contact — tier-1 mutual-CONTACT
   *  discovery, NOT reciprocal "peer trusts us" (own fp is never in the blinded set). */
  mutualFingerprints: string[];
  /** Total contacts checked */
  totalChecked: number;
  /** Session ID from satellite */
  sessionId: string;
  /** Whether we initiated or responded */
  role: 'initiator' | 'responder';
}

export interface PSISyncOptions {
  /** Satellite base URL (e.g. https://satellite.nuavalon.com) */
  satelliteUrl: string;
  /** Our fingerprint */
  myFingerprint: string;
  /** Ed25519 signing function: (data, privateKey) => signature */
  signFn: (data: Uint8Array) => Uint8Array;
}

/**
 * Storage-agnostic dependencies for the orchestrator — the zero-knowledge seam.
 *
 * The orchestrator NEVER touches the filesystem or the owner's private key/passphrase.
 * The caller (browser client-store, or a local CLI) decrypts its OWN trust graph where
 * the key lives and provides:
 *  - getTrustedPeers: the peers this owner trusts (already decrypted + trust-filtered),
 *    each with an optional lastSync for the staleness scheduler. Fingerprints are blinded
 *    before anything leaves the device; the satellite only ever sees blinded points.
 *  - applyMutualResult: sink to persist the discovered mutual-CONTACT state to the
 *    caller's store. `sharesTrustedContact` = we share >=1 trusted contact with the peer
 *    (tier-1 discovery) — it is NOT "the peer trusts us" (our own fingerprint is never in
 *    our blinded set, so the intersection cannot reveal reciprocal trust). `matched`
 *    carries named shared contacts for P2 named-mode (empty in tier-1).
 */
export interface OrchestratorDeps {
  getTrustedPeers: () => Promise<Array<{ fingerprint: string; lastSync?: string | null }>>;
  applyMutualResult: (
    peerFingerprint: string,
    sharesTrustedContact: boolean,
    matched?: string[]
  ) => Promise<void>;
}

// --- Crypto Primitives (mirrors crypto_utils.py) ---

/**
 * Generate an ephemeral X25519 keypair for one PSI session.
 * MUST be discarded after use — never reuse across sessions.
 */
export function generatePSIKeypair(): PSIKeypair {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    privateKey: toBase64(privateKey),
    publicKey: toBase64(publicKey),
  };
}

/**
 * Hash a fingerprint to an X25519 u-coordinate (canonical H(fp)).
 * H(fp) = HKDF-SHA256(ikm=utf8(fp), salt=PSI_SALT, info=PSI_POINT_INFO, 32) → raw 32B u-coord, NO clamp.
 * MUST match client-kit/crypto_utils.py _hash_fingerprint_to_point() byte-for-byte, or cross-impl
 * PSI intersections are silently empty (the B3 bug). Locked vector
 * (FP_PINNED d7f54122… → 593f2af2…).
 * Clamp removed: it was a SCALAR op misapplied to a point; the ephemeral PSI scalar is clamped by
 * X25519 (RFC 7748), which annihilates the cofactor. getSharedSecret rejects all-zero (low-order u).
 */
export function hashFingerprintToPoint(fingerprint: string): Uint8Array {
  const ikm = new TextEncoder().encode(fingerprint);
  const salt = new TextEncoder().encode(PSI_SALT);
  const info = new TextEncoder().encode(PSI_POINT_INFO);
  return hkdf(sha256, ikm, salt, info, 32);
}

/**
 * Blind a set of fingerprints with our ephemeral PSI key.
 * Each fingerprint is hashed to a curve point, then ECDH'd with our key.
 * Result is shuffled to prevent ordering leaks.
 */
export function blindFingerprints(
  fingerprints: string[],
  psiPrivateKeyB64: string
): string[] {
  const sk = fromBase64(psiPrivateKeyB64);
  const blinded: string[] = [];
  for (const fp of fingerprints) {
    try {
      const point = hashFingerprintToPoint(fp);
      blinded.push(toBase64(x25519.getSharedSecret(sk, point)));
    } catch {
      // B6 / low-order guard: getSharedSecret rejects a low-order/degenerate H(fp)
      // (negligible, ~2^-250). Skip it → this fp simply won't match. Never crash the sync.
    }
  }
  // Shuffle to prevent position correlation
  return shuffle(blinded);
}

/**
 * Re-blind another party's blinded set with our key.
 * Due to DH commutativity: ECDH(sk_A, ECDH(sk_B, H(fp))) == ECDH(sk_B, ECDH(sk_A, H(fp)))
 * This means both parties' doubly-blinded values match for shared fingerprints.
 */
export function reblindSet(
  theirBlindedValues: string[],
  psiPrivateKeyB64: string
): string[] {
  const sk = fromBase64(psiPrivateKeyB64);
  const reblinded: string[] = [];
  for (const b64 of theirBlindedValues) {
    try {
      const point = fromBase64(b64);
      reblinded.push(toBase64(x25519.getSharedSecret(sk, point)));
    } catch {
      // B6 / low-order guard: a peer may send a low-order/degenerate point (crafted or
      // corrupt) — getSharedSecret rejects it. Skip → no-match, never crash the sync.
      // Set-based intersection is index-free, so dropping a degenerate value is safe.
    }
  }
  return reblinded;
}

/**
 * Compute the PSI intersection.
 * Returns indices into myReblinded that have matches in theirReblinded.
 */
function computeIntersection(
  myReblinded: string[],
  theirReblinded: string[]
): Set<number> {
  const theirSet = new Set(theirReblinded);
  const matches = new Set<number>();
  for (let i = 0; i < myReblinded.length; i++) {
    if (theirSet.has(myReblinded[i])) {
      matches.add(i);
    }
  }
  return matches;
}

// --- Satellite API Client ---

/**
 * Auth signature in the satellite's scheme (satellite.py verify_request_signature):
 * Ed25519(signFn, "{fingerprint}:{unixSeconds}"), sent as "{unixSeconds}:{b64sig}" (±30s window).
 * The caller's OWN fingerprint is always the one bound. Replaces the old per-action JSON
 * payloads, which the satellite never verified. (Follow-up: bind sig to request body/action —
 * server+client hardening; TLS covers transit for now.)
 */
function buildAuthSignature(myFingerprint: string, signFn: (data: Uint8Array) => Uint8Array): string {
  const ts = Math.floor(Date.now() / 1000);
  const sig = signFn(new TextEncoder().encode(`${myFingerprint}:${ts}`));
  return `${ts}:${toBase64(sig)}`;
}

/**
 * Initiate a PSI session with a specific peer.
 * Sends our blinded trust set to the satellite.
 */
async function psiInitiate(
  satelliteUrl: string,
  myFingerprint: string,
  peerFingerprint: string,
  blindedSet: string[],
  signFn: (data: Uint8Array) => Uint8Array
): Promise<{ sessionId: string } | { error: string }> {
  const body = {
    initiator_fingerprint: myFingerprint,
    responder_fingerprint: peerFingerprint,
    blinded_set: blindedSet,
    signature: buildAuthSignature(myFingerprint, signFn),
  };

  const res = await fetch(`${satelliteUrl}/trust/psi/initiate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    return { error: `PSI initiate failed (${res.status}): ${text}` };
  }

  const data = await res.json();
  return { sessionId: data.session_id };
}

/**
 * Check for pending PSI sessions addressed to us.
 */
async function psiPending(
  satelliteUrl: string,
  myFingerprint: string,
  signFn: (data: Uint8Array) => Uint8Array
): Promise<Array<{ session_id: string; initiator: string; created_at: number }>> {
  const res = await fetch(`${satelliteUrl}/trust/psi/pending/${myFingerprint}`, {
    headers: { 'X-Signature': buildAuthSignature(myFingerprint, signFn) },
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.pending_sessions ?? [];
}

/**
 * Fetch the initiator's blinded set for a session.
 */
async function psiGetBlinded(
  satelliteUrl: string,
  sessionId: string,
  myFingerprint: string,
  signFn: (data: Uint8Array) => Uint8Array
): Promise<string[] | null> {
  const signature = buildAuthSignature(myFingerprint, signFn);

  const res = await fetch(
    `${satelliteUrl}/trust/psi/session/${sessionId}/blinded?fingerprint=${myFingerprint}`,
    { headers: { 'X-Signature': signature } }
  );
  if (!res.ok) return null;
  const data = await res.json();
  return data.blinded_set ?? null;
}

/**
 * Respond to a PSI session with our blinded set + re-blinded initiator set.
 */
async function psiRespond(
  satelliteUrl: string,
  sessionId: string,
  myFingerprint: string,
  blindedSet: string[],
  reblindedInitiatorSet: string[],
  signFn: (data: Uint8Array) => Uint8Array
): Promise<boolean> {
  const body = {
    responder_fingerprint: myFingerprint,
    blinded_set: blindedSet,
    reblinded_initiator_set: reblindedInitiatorSet,
    signature: buildAuthSignature(myFingerprint, signFn),
  };

  const res = await fetch(`${satelliteUrl}/trust/psi/session/${sessionId}/respond`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.ok;
}

/**
 * Fetch PSI session result (initiator only — after responder has submitted).
 */
async function psiGetResult(
  satelliteUrl: string,
  sessionId: string,
  myFingerprint: string,
  signFn: (data: Uint8Array) => Uint8Array
): Promise<{
  responder_blinded_set: string[];
  reblinded_initiator_set: string[];
} | null> {
  const signature = buildAuthSignature(myFingerprint, signFn);

  const res = await fetch(
    `${satelliteUrl}/trust/psi/session/${sessionId}/result?fingerprint=${myFingerprint}`,
    { headers: { 'X-Signature': signature } }
  );
  if (!res.ok) return null;
  return await res.json();
}

// --- High-Level Sync Operations ---

/**
 * Initiate mutual trust sync with a specific peer.
 * Call this on app open or periodic sync for each trusted contact.
 *
 * Flow:
 * 1. Generate ephemeral PSI keypair
 * 2. Blind our trusted fingerprints
 * 3. Send to satellite via /trust/psi/initiate
 * 4. Return session ID — poll psiGetResult() later for completion
 */
export async function initiateTrustSync(
  deps: OrchestratorDeps,
  peerFingerprint: string,
  options: PSISyncOptions
): Promise<{ sessionId: string; keypair: PSIKeypair } | { error: string }> {
  // Load trusted fingerprints from local graph
  const trustedFps = await getTrustedFingerprints(deps);
  if (trustedFps.length === 0) {
    return { error: 'No trusted contacts to sync' };
  }

  // Generate ephemeral keypair
  const keypair = generatePSIKeypair();

  // Blind our trust set
  const blindedSet = blindFingerprints(trustedFps, keypair.privateKey);

  // Send to satellite
  const result = await psiInitiate(
    options.satelliteUrl,
    options.myFingerprint,
    peerFingerprint,
    blindedSet,
    options.signFn
  );

  if ('error' in result) return result;
  return { sessionId: result.sessionId, keypair };
}

/**
 * Complete an initiated PSI session (initiator side).
 * Call after responder has submitted their response.
 *
 * Flow:
 * 1. Fetch result from satellite
 * 2. Re-blind responder's set with our key
 * 3. Compare against our re-blinded set (from responder)
 * 4. Intersection = mutual contacts
 * 5. Update trust graph
 */
export async function completeTrustSync(
  deps: OrchestratorDeps,
  sessionId: string,
  peerFingerprint: string,
  keypair: PSIKeypair,
  options: PSISyncOptions
): Promise<PSISyncResult | { error: string }> {
  // Fetch result
  const result = await psiGetResult(
    options.satelliteUrl,
    sessionId,
    options.myFingerprint,
    options.signFn
  );

  if (!result) {
    return { error: 'Session not ready or not found' };
  }

  // Re-blind responder's set with our key
  const theirReblinded = reblindSet(result.responder_blinded_set, keypair.privateKey);

  // Our set was re-blinded by responder — compare
  const myReblinded = result.reblinded_initiator_set;

  // Find intersection
  const matches = computeIntersection(myReblinded, theirReblinded);

  // What the intersection means (and does NOT mean):
  // `matches` = contacts present in BOTH our trusted set and the peer's — i.e. shared
  // trusted CONTACTS. It is NOT "the peer trusts us": our own fingerprint is never in our
  // blinded set (getTrustedPeers returns PEERS), so the intersection can never contain us
  // and can never reveal reciprocal trust. matches.size > 0 therefore means only "we share
  // >=1 trusted contact with this peer" — tier-1 mutual-CONTACT discovery, nothing more.
  // (P2 named-mode maps matches back to names via a caller-side {blinded->fp} map;
  // reciprocal-trust attestation is tier-2, a separate construction.)

  const sharesTrustedContact = matches.size > 0;

  // Persist the discovered mutual-CONTACT state via the caller's sink (client-store).
  try {
    await deps.applyMutualResult(peerFingerprint, sharesTrustedContact, []);
  } catch {
    // Sink may reject an unknown peer — that's OK for discovery
  }

  return {
    mutualFingerprints: sharesTrustedContact ? [peerFingerprint] : [],
    totalChecked: myReblinded.length,
    sessionId,
    role: 'initiator',
  };
}

/**
 * Respond to a pending PSI session (responder side).
 *
 * Flow:
 * 1. Check pending sessions
 * 2. For each: fetch initiator's blinded set
 * 3. Re-blind their set with our key
 * 4. Blind our own set
 * 5. Submit response
 * 6. Compute intersection from our doubly-blinded values
 * 7. Update trust graph
 */
export async function respondToTrustSync(
  deps: OrchestratorDeps,
  options: PSISyncOptions
): Promise<PSISyncResult[]> {
  const results: PSISyncResult[] = [];

  // Check for pending sessions
  const pending = await psiPending(options.satelliteUrl, options.myFingerprint, options.signFn);
  if (pending.length === 0) return results;

  // Load our trusted fingerprints once
  const trustedFps = await getTrustedFingerprints(deps);
  if (trustedFps.length === 0) return results;

  for (const session of pending) {
    // Skip expired sessions
    const age = Date.now() - session.created_at * 1000;
    if (age > PSI_SESSION_TTL_MS) continue;

    // Generate ephemeral keypair for this session
    const keypair = generatePSIKeypair();

    // Fetch initiator's blinded set
    const initiatorBlinded = await psiGetBlinded(
      options.satelliteUrl,
      session.session_id,
      options.myFingerprint,
      options.signFn
    );
    if (!initiatorBlinded) continue;

    // Re-blind initiator's set with our key
    const reblindedInitiator = reblindSet(initiatorBlinded, keypair.privateKey);

    // Blind our own set
    const ourBlinded = blindFingerprints(trustedFps, keypair.privateKey);

    // Submit response
    const ok = await psiRespond(
      options.satelliteUrl,
      session.session_id,
      options.myFingerprint,
      ourBlinded,
      reblindedInitiator,
      options.signFn
    );
    if (!ok) continue;

    // We can compute our side of the intersection immediately:
    // We have initiator's set blinded by THEIR key.
    // We re-blinded it with OUR key → doubly-blinded by both.
    // We blinded our set with OUR key only.
    // We need THEIR re-blinding of our set for comparison.
    //
    // As responder, we DON'T get the initiator's re-blinding of our set.
    // The initiator computes the final intersection.
    // The initiator persists the shared-contact result on their end (applyMutualResult);
    // our own next sync as initiator computes our side independently.
    //
    // For now: mark that we participated. The initiator drives the update.

    results.push({
      mutualFingerprints: [], // Responder can't compute intersection alone
      totalChecked: trustedFps.length,
      sessionId: session.session_id,
      role: 'responder',
    });
  }

  return results;
}

/**
 * Full sync cycle — check for pending sessions (respond), then initiate new ones.
 * Designed to run on app open or periodic timer.
 */
export async function syncMutualTrust(
  deps: OrchestratorDeps,
  options: PSISyncOptions
): Promise<{
  responded: PSISyncResult[];
  initiated: Array<{ peerFingerprint: string; sessionId: string; keypair: PSIKeypair }>;
  errors: string[];
}> {
  const responded: PSISyncResult[] = [];
  const initiated: Array<{ peerFingerprint: string; sessionId: string; keypair: PSIKeypair }> = [];
  const errors: string[] = [];

  // Step 1: Respond to any pending sessions
  try {
    const responses = await respondToTrustSync(deps, options);
    responded.push(...responses);
  } catch (e) {
    errors.push(`Respond phase: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Step 2: Initiate sessions with trusted contacts that haven't synced recently
  try {
    const stalePeers = await getStaleMutualPeers(deps);
    for (const peerFp of stalePeers) {
      const result = await initiateTrustSync(deps, peerFp, options);
      if ('error' in result) {
        errors.push(`Initiate ${peerFp.slice(0, 8)}...: ${result.error}`);
      } else {
        initiated.push({
          peerFingerprint: peerFp,
          sessionId: result.sessionId,
          keypair: result.keypair,
        });
      }
    }
  } catch (e) {
    errors.push(`Initiate phase: ${e instanceof Error ? e.message : String(e)}`);
  }

  return { responded, initiated, errors };
}

// --- Trust Graph Helpers ---

/**
 * Get fingerprints of all peers we trust (from the caller's decrypted store).
 */
async function getTrustedFingerprints(deps: OrchestratorDeps): Promise<string[]> {
  const peers = await deps.getTrustedPeers();
  return peers.map(p => p.fingerprint);
}

/**
 * Get trusted contacts whose mutual state is stale (>24h since last sync).
 * These are candidates for a new PSI session.
 */
async function getStaleMutualPeers(
  deps: OrchestratorDeps,
  maxAgeMs: number = 24 * 60 * 60 * 1000
): Promise<string[]> {
  const peers = await deps.getTrustedPeers();
  const now = Date.now();

  return peers
    .filter(p => {
      if (!p.lastSync) return true; // Never synced
      const syncAge = now - new Date(p.lastSync).getTime();
      return syncAge > maxAgeMs;
    })
    .map(p => p.fingerprint);
}

// --- Utilities ---

function toBase64(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    return btoa(String.fromCharCode(...bytes));
  }
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(b64: string): Uint8Array {
  if (typeof atob === 'function') {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/** Unbiased random integer in [0, n) via rejection sampling on a CSPRNG (randomBytes). */
function randBelow(n: number): number {
  if (n <= 1) return 0;
  const limit = Math.floor(0x100000000 / n) * n;
  let x: number;
  do {
    const b = randomBytes(4);
    x = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  } while (x >= limit);
  return x % n;
}

/** Fisher-Yates shuffle (CSPRNG) — prevents position correlation in blinded sets. */
function shuffle<T>(array: T[]): T[] {
  const result = [...array];
  for (let i = result.length - 1; i > 0; i--) {
    const j = randBelow(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}
