// src/lib/relay/mailbox-auth-v2.ts
// #721 D1 + D2 (Flint design v2 a494590d + addendum A, contract b436ba7e): an UNLINKABLE mailbox address and its owner proof.
//
// v1 (mailbox-auth.ts) derives the mailbox id from the identity fingerprint and proves ownership with an identity-signed bundle that
// carries the fingerprint and identity key, so the relay (or anyone holding the public card) can tie every poll, ack and deposit to a
// person. v2 removes both links:
//   D1  mailbox_id = 'mbx2_' + sha256(LP('svrnty:mailbox-id:v2') ‖ LP(ed25519_pub) ‖ LP(ml_dsa87_pub)) over a RANDOM hybrid
//       signing key that is not the identity key, not the device-mailbox (seal) key, and NEVER on the card (R1: two keys, two jobs).
//       Given only a card, nobody can compute or recognise the id.
//   D2  poll / ack / claim are signed by that key under 'svrnty:mailbox-owner:v2', over LP(domain) ‖ LP(op) ‖ LP(canonical claim).
//       The bundle has no fingerprint, identity key or identity signature field at all; unknown keys are refused.
// Both halves must verify (Ed25519 AND ML-DSA-87, the identity's PQ parameter set). Like v1, the client signer and the server
// verifier live in THIS module so the wire encoding cannot drift. Verifiers return false, never throw.

import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { canonicalize } from '@/lib/format/canonical';
import { lpBin, lpStr } from '@/lib/crypto/lp-tlv';
import { mailboxConfig } from './mailbox-config';

export const DOMAIN_MAILBOX_ID_V2 = 'svrnty:mailbox-id:v2';
export const DOMAIN_MAILBOX_OWNER_V2 = 'svrnty:mailbox-owner:v2';
/** A separate header from v1's, so a v1 bundle can never be read as a v2 one (and vice-versa). */
export const OWNER_AUTH_V2_HEADER = 'x-svrnty-owner-auth-v2';
export const MAILBOX_ID_V2_PREFIX = 'mbx2_';

export type OwnerOpV2 = 'poll' | 'ack' | 'claim';
const OPS: ReadonlySet<string> = new Set<OwnerOpV2>(['poll', 'ack', 'claim']);

export const ED_PUB_LEN = 32;
export const ED_SIG_LEN = 64;
export const DSA_PUB_LEN = 2592; // ML-DSA-87
export const DSA_SIG_LEN = 4627;

/** The mailbox AUTH keypair. Vault-held next to device_mailbox (#721 I2); never on the card, never sent except the public half in a bundle. */
export interface MailboxAuthKeypair {
  edSecretKey: Uint8Array;
  edPublicKey: Uint8Array;
  dsaSecretKey: Uint8Array;
  dsaPublicKey: Uint8Array;
}
export type MailboxAuthPublic = Pick<MailboxAuthKeypair, 'edPublicKey' | 'dsaPublicKey'>;

/** Fresh random keys: nothing about the identity goes in, so the id below is independent of it (and survives identity rotation, R2b). */
export function generateMailboxAuthKeypair(): MailboxAuthKeypair {
  const edSecretKey = ed25519.utils.randomSecretKey();
  const dsa = ml_dsa87.keygen(randomBytes(32));
  return { edSecretKey, edPublicKey: ed25519.getPublicKey(edSecretKey), dsaSecretKey: dsa.secretKey, dsaPublicKey: dsa.publicKey };
}

export function deriveMailboxIdV2(pub: MailboxAuthPublic): string {
  if (pub.edPublicKey.length !== ED_PUB_LEN || pub.dsaPublicKey.length !== DSA_PUB_LEN) throw new Error('mailbox auth key: wrong length');
  return MAILBOX_ID_V2_PREFIX + bytesToHex(sha256(concatBytes(lpStr(DOMAIN_MAILBOX_ID_V2), lpBin(pub.edPublicKey), lpBin(pub.dsaPublicKey))));
}

const ID_V2 = /^mbx2_[0-9a-f]{64}$/;
export function isMailboxIdV2(id: unknown): id is string {
  return typeof id === 'string' && ID_V2.test(id);
}

// The claim the owner signs: the same shapes as v1 (poll/claim bind {mailbox_id, nonce, ts}; ack also binds the exact envelope_ids).
function claimJson(op: OwnerOpV2, mailboxId: string, nonce: string, ts: number, envelopeIds?: string[]): string {
  return op === 'ack'
    ? canonicalize({ mailbox_id: mailboxId, envelope_ids: envelopeIds ?? [], nonce, ts })
    : canonicalize({ mailbox_id: mailboxId, nonce, ts });
}
function signedMessage(op: OwnerOpV2, claim: string): Uint8Array {
  return concatBytes(lpStr(DOMAIN_MAILBOX_OWNER_V2), lpStr(op), lpStr(claim));
}

/** The wire bundle (base64url JSON in {@link OWNER_AUTH_V2_HEADER}). These keys and NO others. */
interface OwnerAuthV2Bundle {
  v: 2;
  ed_pub: string;
  dsa_pub: string;
  nonce: string;
  ts: number;
  sig: string;
  pq_sig: string;
}
const BUNDLE_KEYS = ['dsa_pub', 'ed_pub', 'nonce', 'pq_sig', 'sig', 'ts', 'v'];
const NONCE = /^[0-9a-f]{32}$/;

// --- cross-env base64url (browser client + Node server both run this module) ---
function bytesToB64url(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBytes(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('not base64url');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeBundle(header: string | null): OwnerAuthV2Bundle | null {
  if (!header) return null;
  try {
    const b = JSON.parse(new TextDecoder().decode(b64urlToBytes(header)));
    if (!b || typeof b !== 'object' || Array.isArray(b)) return null;
    if (Object.keys(b).sort().join(',') !== BUNDLE_KEYS.join(',')) return null; // no fingerprint / identity field can ride along
    if (b.v !== 2 || !Number.isFinite(b.ts) || typeof b.nonce !== 'string' || !NONCE.test(b.nonce)) return null;
    for (const k of ['ed_pub', 'dsa_pub', 'sig', 'pq_sig']) if (typeof b[k] !== 'string') return null;
    return b as OwnerAuthV2Bundle;
  } catch {
    return null;
  }
}

// ── CLIENT: sign a poll / ack / claim for THIS key's own mailbox ──

export function signOwnerRequestV2(args: {
  keypair: MailboxAuthKeypair;
  op: OwnerOpV2;
  now: number;
  envelopeIds?: string[];
}): { mailboxId: string; headers: Record<string, string> } {
  const mailboxId = deriveMailboxIdV2(args.keypair);
  const nonce = bytesToHex(randomBytes(16));
  const msg = signedMessage(args.op, claimJson(args.op, mailboxId, nonce, args.now, args.envelopeIds));
  const bundle: OwnerAuthV2Bundle = {
    v: 2,
    ed_pub: bytesToB64url(args.keypair.edPublicKey),
    dsa_pub: bytesToB64url(args.keypair.dsaPublicKey),
    nonce,
    ts: args.now,
    sig: bytesToB64url(ed25519.sign(msg, args.keypair.edSecretKey)),
    pq_sig: bytesToB64url(ml_dsa87.sign(msg, args.keypair.dsaSecretKey)),
  };
  return { mailboxId, headers: { [OWNER_AUTH_V2_HEADER]: bytesToB64url(new TextEncoder().encode(JSON.stringify(bundle))) } };
}

// ── SERVER: verify a request is from the owner of THIS v2 mailbox. Before any store access (I-4), never throws. ──

export async function verifyOwnerRequestV2(
  request: Request,
  op: OwnerOpV2,
  mailboxId: string,
  now: number,
  envelopeIds?: string[],
): Promise<boolean> {
  try {
    if (!OPS.has(op) || !isMailboxIdV2(mailboxId)) return false;
    const b = decodeBundle(request.headers.get(OWNER_AUTH_V2_HEADER));
    if (!b) return false;
    // (1) freshness, the same window as v1.
    if (Math.abs(now - b.ts) > mailboxConfig().ownerAuthWindowMs) return false;
    // (2) the presented key must derive THIS mailbox id.
    const pub = { edPublicKey: b64urlToBytes(b.ed_pub), dsaPublicKey: b64urlToBytes(b.dsa_pub) };
    if (pub.edPublicKey.length !== ED_PUB_LEN || pub.dsaPublicKey.length !== DSA_PUB_LEN) return false;
    if (deriveMailboxIdV2(pub) !== mailboxId) return false;
    // (3) possession of BOTH halves over exactly this request, under the op.
    const sig = b64urlToBytes(b.sig);
    const pq = b64urlToBytes(b.pq_sig);
    if (sig.length !== ED_SIG_LEN || pq.length !== DSA_SIG_LEN) return false;
    const msg = signedMessage(op, claimJson(op, mailboxId, b.nonce, b.ts, envelopeIds));
    if (!ed25519.verify(sig, msg, pub.edPublicKey)) return false;
    return ml_dsa87.verify(pq, msg, pub.dsaPublicKey);
  } catch {
    return false;
  }
}
