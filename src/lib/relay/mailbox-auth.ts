// src/lib/relay/mailbox-auth.ts
// Owner-ownership proof for the return-channel mailbox (joint §4, Q1 seam #116216). The owner proves
// control of the identity key behind the mailbox by SIGNING the request — a SIGNED POLL REQUEST, not
// a bearer token (smaller surface, no token-issuance endpoint).
//
// This mirrors src/lib/trust/slug-claim.ts EXACTLY — the same proven envelope: signWithEnvelope over a
// canonical() input under a domain tag, verified with verifyWithEnvelope + fingerprintMatchesKey. The
// identity key is openpgp (fingerprint.ts / sign-envelope.ts), so we reuse those primitives verbatim
// rather than assume the ratified-but-unshipped raw-Ed25519 model-B.
//
// mailbox_id = deriveMailboxId(fingerprint) (Q2 demo default). DOCUMENTED LEAK: the derivation is
// deterministic from the identity fingerprint, so the relay / an observer can link identity ↔ mailbox
// ↔ presence/poll-cadence. Bounded by I-4 (a non-owner can't probe existence/occupancy) + rider (b)
// rotation; hardening = a blinded, rotating mailbox-id + a mailbox-scoped capability key (post-9/10,
// propose-first). Both the client signer and the server verifier live in THIS module, so the exact
// wire encoding cannot drift; promote the domain tags to format/envelope.ts only if another agent's
// code ever needs them.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize } from '@/lib/format/canonical';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '@/lib/crypto/sign-envelope';
import { fingerprintMatchesKey, KEM_PUB_LEN, SIG_PUB_LEN } from '@/lib/identity/fingerprint';
import { mailboxConfig } from './mailbox-config';

// Domain-separation tags for the two owner-authenticated mailbox ops. A poll signature can never be
// replayed as an ack (or vice-versa): different domain → different signed bytes (sign-envelope LP).
export const DOMAIN_MAILBOX_POLL = 'svrnty:mailbox-poll:v1';
export const DOMAIN_MAILBOX_ACK = 'svrnty:mailbox-ack:v1';

/** The HTTP header carrying the base64url(JSON) owner-auth bundle for both poll (GET) and ack (POST). */
export const OWNER_AUTH_HEADER = 'x-svrnty-owner-auth';

/** mailbox_id = hash(fingerprint) — deterministic (documented leak, Q2). */
export function deriveMailboxId(fingerprint: string): string {
  return 'mbx_' + bytesToHex(sha256(utf8ToBytes('svrnty:mailbox-id:v1|' + fingerprint.toUpperCase())));
}

// The claim the owner signs. Poll binds {mailbox_id, nonce, ts}; ack additionally binds the exact
// envelope_ids being deleted, so a captured poll-auth can never delete and a tampered id-list fails.
interface PollClaim {
  mailbox_id: string;
  nonce: string;
  ts: number;
}
interface AckClaim extends PollClaim {
  envelope_ids: string[];
}

function pollSigningInput(c: PollClaim): string {
  return canonicalize(c);
}
function ackSigningInput(c: AckClaim): string {
  return canonicalize(c);
}

/**
 * The wire bundle carried in the {@link OWNER_AUTH_HEADER} (base64url JSON). Carries the verifier's
 * inputs: the presenter's identity key, the freshness fields, and the signature. mailbox_id and
 * envelope_ids are read from the request (query/body) and folded into the recomputed signing input —
 * so tampering either fails the signature.
 */
export interface OwnerAuthBundle {
  fingerprint: string;
  public_key: string; // openpgp armored — the signature verifies against this; fp↔key bound below
  nonce: string;
  ts: number;
  signature: string; // classical (Ed25519 / PGP)
  pq_signature?: string;
  // §5 canonical-id binding: the identity's PQ PUBLIC keys, so the verifier can recompute the
  // 64-hex canonical fingerprint = SHA256(sign‖enc‖kem‖sig) and confirm fp↔key. Absent for a
  // classical (40-hex OpenPGP) identity → fingerprintMatchesKey falls back to the getFingerprint()
  // path. Public keys only — the wire exposes nothing secret; possession is proved by the signature.
  kem_public_key?: string; // ML-KEM-1024 public, base64 (1568 bytes)
  sig_public_key?: string; // ML-DSA-87 public, base64 (2592 bytes)
}

// --- cross-env base64url (browser client + Node server both run this module) ---
function b64urlEncode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s: string): string {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function encodeBundle(b: OwnerAuthBundle): string {
  return b64urlEncode(JSON.stringify(b));
}

function decodeBundle(headerValue: string | null): OwnerAuthBundle | null {
  if (!headerValue) return null;
  try {
    const b = JSON.parse(b64urlDecode(headerValue));
    if (
      typeof b?.fingerprint === 'string' &&
      typeof b?.public_key === 'string' &&
      typeof b?.nonce === 'string' &&
      typeof b?.ts === 'number' &&
      typeof b?.signature === 'string' &&
      (b.kem_public_key === undefined || typeof b.kem_public_key === 'string') &&
      (b.sig_public_key === undefined || typeof b.sig_public_key === 'string')
    ) {
      // §5 defense-in-depth (Flint #130212): fail-LOUD on malformed/wrong-length PQ pubkeys at the
      // boundary, not only via fingerprintMatchesKey's downstream canonical-branch length gate. A
      // canonical bundle carries BOTH kem+sig at FIPS length; reject a half-present or wrong-length pair.
      const hasKem = typeof b.kem_public_key === 'string';
      const hasSig = typeof b.sig_public_key === 'string';
      if (hasKem !== hasSig) return null; // half-present ⇒ malformed
      if (hasKem && hasSig) {
        try {
          if (atob(b.kem_public_key).length !== KEM_PUB_LEN) return null;
          if (atob(b.sig_public_key).length !== SIG_PUB_LEN) return null;
        } catch {
          return null; // undecodable base64 ⇒ reject
        }
      }
      return b as OwnerAuthBundle;
    }
    return null;
  } catch {
    return null;
  }
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

// ── CLIENT (browser): sign a poll / ack request as the mailbox owner ──

/** Build the owner-auth header for a poll of `mailboxId`. Requires the owner's identity keypair. */
export async function signMailboxPollRequest(args: {
  mailboxId: string;
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  now: number;
  kemPublicKey?: string; // §5: identity's ML-KEM-1024 public (base64) — canonical-fp binding
  sigPublicKey?: string; // §5: identity's ML-DSA-87 public (base64) — canonical-fp binding
}): Promise<Record<string, string>> {
  const nonce = randomNonce();
  const sig = await signWithEnvelope(
    DOMAIN_MAILBOX_POLL,
    pollSigningInput({ mailbox_id: args.mailboxId, nonce, ts: args.now }),
    args.privateKeyArmored,
    args.passphrase,
  );
  return { [OWNER_AUTH_HEADER]: encodeBundle(bundleFrom(args, nonce, sig)) };
}

/** Build the owner-auth header for an ack-delete of `envelopeIds` from `mailboxId`. */
export async function signMailboxAckRequest(args: {
  mailboxId: string;
  envelopeIds: string[];
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  now: number;
  kemPublicKey?: string; // §5: identity's ML-KEM-1024 public (base64) — canonical-fp binding
  sigPublicKey?: string; // §5: identity's ML-DSA-87 public (base64) — canonical-fp binding
}): Promise<Record<string, string>> {
  const nonce = randomNonce();
  const sig = await signWithEnvelope(
    DOMAIN_MAILBOX_ACK,
    ackSigningInput({ mailbox_id: args.mailboxId, envelope_ids: args.envelopeIds, nonce, ts: args.now }),
    args.privateKeyArmored,
    args.passphrase,
  );
  return { [OWNER_AUTH_HEADER]: encodeBundle(bundleFrom(args, nonce, sig)) };
}

function bundleFrom(
  args: { fingerprint: string; publicKeyArmored: string; now: number; kemPublicKey?: string; sigPublicKey?: string },
  nonce: string,
  sig: EnvelopeSignature,
): OwnerAuthBundle {
  const b: OwnerAuthBundle = {
    fingerprint: args.fingerprint,
    public_key: args.publicKeyArmored,
    nonce,
    ts: args.now,
    signature: sig.classical,
  };
  if (sig.pq_signature) b.pq_signature = sig.pq_signature;
  // §5: carry the identity's PQ pubkeys so verifyOwner can recompute the canonical fp. Only when
  // BOTH are present (a canonical identity); a classical identity omits them → OpenPGP-fp fallback.
  if (args.kemPublicKey && args.sigPublicKey) {
    b.kem_public_key = args.kemPublicKey;
    b.sig_public_key = args.sigPublicKey;
  }
  return b;
}

// ── SERVER (Next API route): verify a poll / ack request is from the mailbox owner ──
// Verified BEFORE any store access → a non-owner never reaches the store (I-4 anti-oracle). Returns
// false, never throws — a verifier refuses.

export async function verifyMailboxPollAuth(request: Request, mailboxId: string, now: number): Promise<boolean> {
  const bundle = decodeBundle(request.headers.get(OWNER_AUTH_HEADER));
  if (!bundle) return false;
  const input = pollSigningInput({ mailbox_id: mailboxId, nonce: bundle.nonce, ts: bundle.ts });
  return verifyOwner(bundle, DOMAIN_MAILBOX_POLL, input, mailboxId, now);
}

export async function verifyMailboxAckAuth(
  request: Request,
  mailboxId: string,
  envelopeIds: string[],
  now: number,
): Promise<boolean> {
  const bundle = decodeBundle(request.headers.get(OWNER_AUTH_HEADER));
  if (!bundle) return false;
  const input = ackSigningInput({ mailbox_id: mailboxId, envelope_ids: envelopeIds, nonce: bundle.nonce, ts: bundle.ts });
  return verifyOwner(bundle, DOMAIN_MAILBOX_ACK, input, mailboxId, now);
}

async function verifyOwner(
  bundle: OwnerAuthBundle,
  domain: string,
  signingInput: string,
  mailboxId: string,
  now: number,
): Promise<boolean> {
  try {
    // (1) freshness — bound replay of a captured request to the configured window.
    if (!Number.isFinite(bundle.ts) || Math.abs(now - bundle.ts) > mailboxConfig().ownerAuthWindowMs) return false;
    // (2) mailbox binding — the presented fingerprint must derive THIS mailbox_id (owner-of-record).
    if (deriveMailboxId(bundle.fingerprint) !== mailboxId) return false;
    // (3) fp↔key binding (Canon Invariant-1) — the key can't be swapped under the fingerprint.
    //     §5: pass the PQ pubkeys so a 64-hex canonical id recomputes SHA256(sign‖enc‖kem‖sig) and
    //     matches. fingerprintMatchesKey length-gates them (kem=1568/sig=2592) and falls back to the
    //     40-hex OpenPGP path for a classical id — so absent/short pq ⇒ a canonical id fails-closed.
    if (!(await fingerprintMatchesKey(bundle.fingerprint, bundle.public_key, {
      kem_public_key: bundle.kem_public_key,
      sig_public_key: bundle.sig_public_key,
    }))) return false;
    // (4) private-key possession over EXACTLY this request, under the op-specific domain.
    const envSig: EnvelopeSignature = bundle.pq_signature
      ? { classical: bundle.signature, pq_signature: bundle.pq_signature }
      : { classical: bundle.signature };
    return await verifyWithEnvelope(domain, signingInput, envSig, bundle.public_key);
  } catch {
    return false;
  }
}
