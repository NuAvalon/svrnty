// src/lib/crypto/mailbox-registry-client.ts
/**
 * Mailbox registry client — the satellite side of the mailbox lifecycle (KB#90104 items 2-3).
 *
 * REGISTER (POST /mailbox/register): publish a mailbox's PUBLIC keys + owner-proof so peers can seal to
 * it. The satellite stores ONLY pubkeys + a per-mailbox epoch floor (no user content, no PSI/graph). It
 * re-verifies trustlessly: recompute mailbox_fp = SHA256(pubkeys), then Ed25519-verify owner_sig over
 * "svrnty-mailbox-reg-v1:{owner_identity_fp}:{mailbox_fp}:{epoch}" with the IDENTITY key (satellite.py:1092).
 * Register is IDEMPOTENT (fp is a content-address) and one owner may hold MANY mailboxes.
 *
 * FETCH (GET /mailbox/{fp}): retrieve a mailbox's pubkeys to seal to it. The satellite returns pubkeys +
 * epoch ONLY — never owner_identity_fp (privacy I-B). ANTI-SUBSTITUTION MUST (Flint, KB#90104 item 2): the
 * client recomputes SHA256(pubkeys) == requested fp and REJECTS on mismatch BEFORE returning — so a lying
 * relay cannot hand back attacker pubkeys under an honest fp. Enforced here as a hard null-return.
 *
 * HTTP shape mirrors httpTrustRelay (trust-rendezvous.ts): satelliteUrl base, injectable fetchImpl,
 * fail-soft. Register/fetch carry no bearer auth — authority is the owner_sig in the register body and the
 * fp<->pubkeys content-binding on fetch, not endpoint auth.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { uint8ToBase64 } from './pq.js';
import { deriveMailboxFp, type MailboxPublicKeys } from './mailbox-envelope.js';
import type { MailboxKeypair } from './mailbox-keys.js';
import { signMailboxReg } from '../identity/raw-sign.js';

const X25519_HEX = 64; // 32B
const KEM_PUB_HEX = 3136; // 1568B

/** The exact JSON body POSTed to /mailbox/register (satellite MailboxRegisterRequest). */
export interface MailboxRegisterFields {
  mailbox_fp: string; // 64 lowercase hex
  x25519_pk: string; // 64 hex (32B)
  mlkem1024_pk: string; // 3136 hex (1568B)
  owner_identity_fp: string; // full registered identity fingerprint
  epoch: number; // >= 0, per-mailbox floor
  owner_sig: string; // base64 Ed25519 over the reg preimage
}

/** What GET /mailbox/{fp} returns (pubkeys + epoch; NEVER owner_identity_fp). */
export interface MailboxRecord {
  mailbox_fp: string;
  x25519_pk: string;
  mlkem1024_pk: string;
  epoch: number;
}

export interface RegisterResult {
  ok: boolean;
  status: number;
  epoch?: number;
  error?: string;
}

/** Injected transport over the satellite's mailbox endpoints. */
export interface MailboxRegistry {
  register(fields: MailboxRegisterFields): Promise<RegisterResult>;
  /** UNSAFE raw GET — record or null (404 / non-2xx / malformed). Does NOT anti-substitution-check the
   *  fp<->pubkeys binding. NEVER seal to these keys directly — route through fetchMailbox, which enforces
   *  the MUST. Underscore-prefixed so the unsafe path is hard to reach by accident (Flint N3, #141676). */
  _getRaw(mailboxFp: string): Promise<MailboxRecord | null>;
}

/**
 * Assemble the register body from a mailbox keypair + the owner's identity. owner_sig is produced HERE with
 * the identity seed (in-memory only) over the byte-exact preimage. mailbox_fp is DERIVED from the pubkeys
 * (never trusted from a caller) so fp == SHA256(pubkeys) holds by construction.
 */
export function buildMailboxRegisterFields(
  kp: Pick<MailboxKeypair, 'x25519Pub' | 'mlkem1024Pub'>,
  ownerIdentityFp: string,
  epoch: number,
  identitySeed: Uint8Array,
): MailboxRegisterFields {
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error(`epoch must be a non-negative safe integer, got ${epoch}`);
  const mailbox_fp = deriveMailboxFp(kp.x25519Pub, kp.mlkem1024Pub);
  const owner_sig = signMailboxReg(identitySeed, ownerIdentityFp, mailbox_fp, epoch);
  return {
    mailbox_fp,
    x25519_pk: bytesToHex(kp.x25519Pub),
    mlkem1024_pk: bytesToHex(kp.mlkem1024Pub),
    owner_identity_fp: ownerIdentityFp,
    epoch,
    owner_sig: uint8ToBase64(owner_sig),
  };
}

/**
 * FETCH a mailbox's public keys, ENFORCING the anti-substitution MUST: SHA256(pubkeys) must equal the
 * requested fp, or null. Also validates pubkey hex lengths (a malformed record → null, never throws).
 * The returned keys are safe to seal to; a null means "no trustworthy mailbox at this fp" — do NOT seal.
 */
export async function fetchMailbox(registry: MailboxRegistry, mailboxFp: string): Promise<MailboxPublicKeys | null> {
  const rec = await registry._getRaw(mailboxFp);
  if (!rec) return null;
  if (typeof rec.x25519_pk !== 'string' || typeof rec.mlkem1024_pk !== 'string') return null;
  if (rec.x25519_pk.length !== X25519_HEX || rec.mlkem1024_pk.length !== KEM_PUB_HEX) return null;
  let x25519Pub: Uint8Array, mlkem1024Pub: Uint8Array;
  try {
    x25519Pub = hexToBytes(rec.x25519_pk);
    mlkem1024Pub = hexToBytes(rec.mlkem1024_pk);
  } catch {
    return null;
  }
  // ANTI-SUBSTITUTION MUST — hard reject a relay that returns keys not matching the requested fp.
  if (deriveMailboxFp(x25519Pub, mlkem1024Pub) !== mailboxFp) return null;
  return { x25519Pub, mlkem1024Pub };
}

/** Concrete registry over the satellite's /mailbox endpoints. */
export function httpMailboxRegistry(satelliteUrl: string, fetchImpl: typeof fetch = fetch): MailboxRegistry {
  const base = satelliteUrl.replace(/\/$/, '');
  return {
    async register(fields) {
      try {
        const res = await fetchImpl(`${base}/mailbox/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(fields),
        });
        if (!res.ok) {
          let error = `HTTP ${res.status}`;
          try {
            const j = (await res.json()) as { detail?: string };
            if (j?.detail) error = j.detail;
          } catch {
            /* non-JSON body */
          }
          return { ok: false, status: res.status, error };
        }
        const j = (await res.json()) as { status?: string; mailbox_fp?: string; epoch?: number };
        return { ok: true, status: res.status, epoch: j?.epoch };
      } catch (e) {
        return { ok: false, status: 0, error: e instanceof Error ? e.message : 'network error' };
      }
    },
    async _getRaw(mailboxFp) {
      try {
        const res = await fetchImpl(`${base}/mailbox/${encodeURIComponent(mailboxFp)}`);
        if (!res.ok) return null; // 404 unknown / any non-2xx → null
        return (await res.json()) as MailboxRecord;
      } catch {
        return null;
      }
    },
  };
}
