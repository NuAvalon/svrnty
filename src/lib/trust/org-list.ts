// src/lib/trust/org-list.ts
// #705 ORG-1: org v0 = a signed MEMBERSHIP LIST, nothing more. Contract: svrnty_705_introduce_orgs_v2.md (sha256 04e83182…),
// O1–O4 per Flint task:705 #1200/#1494.
//
// WHAT IT SAYS. {v, org_fp, seq, issued_at, expires_at, members:[card_sha256…], constitution_ref}. Admitting an org lets a
// holder show "Member of <org> (as of <date>)" on a listed card. That is ALL. A v0 org cannot act, attest, delegate or
// vouch; nothing here (or in copy) may say "<org> trusts/approves". The domain tag is its own, so an org signature never
// verifies as a vouch, card, agent cert or signal.
// MONOTONIC (O2). One seq per org: a higher seq replaces, a lower one is a rollback, the same seq with a different list is
// equivocation. A held list that EXPIRES is kept only to say we can't confirm membership any more (as of <expiry>), never
// "member", and never "removed": the org may still list them, we just hold no current list (Hypatia task:705 #1509).
// CUSTODY (O1). The org key is the principal's and lives off every agent box: compromising it makes every member
// forgeable, which is why it signs membership only. This module takes the org's secret ONLY in signOrgMemberList, which
// runs in the principal's app; holders get public keys.
// ORG-2 (later) adds the capture-proof org (constitution + k-of-n). v0 reserves `constitution_ref` and REQUIRES it empty,
// so a v0 holder never silently accepts a list that claims a constitution it can't check.

import { canonicalize } from '../format/canonical';
import { DOMAIN_ORG_MEMBER_LIST } from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope } from '../crypto/sign-envelope';
import { base64ToUint8 } from '../crypto/pq';
import { fingerprintMatchesKey } from '../identity/fingerprint';

export const ORG_LIST_VERSION = 1;
export const ORG_LIST_MAX_MEMBERS = 256;
export const ORG_LIST_MAX_LIFETIME_MS = 400 * 24 * 3600 * 1000;
export const ORG_LIST_CLOCK_SKEW_MS = 5 * 60 * 1000;

export interface OrgMemberList {
  v: number;                 // ORG_LIST_VERSION
  org_fp: string;            // 64 lowercase hex: the org's canonical fingerprint
  seq: number;               // monotonic per org, ≥ 1
  issued_at: string;         // YYYY-MM-DDTHH:MM:SSZ
  expires_at: string;        // YYYY-MM-DDTHH:MM:SSZ
  members: string[];         // card sha256s (64 lowercase hex), strictly ascending
  constitution_ref: string;  // RESERVED for ORG-2; must be '' in v0
}

export interface SignedOrgMemberList extends OrgMemberList {
  signature: string;
  pq_signature: string;      // REQUIRED (hybrid only)
}

export interface OrgPublicKeys {
  fingerprint: string;
  publicKey: string;
  kemPublicKeyB64: string;
  sigPublicKeyB64: string;
}

export type OrgRefusal =
  | 'shape' | 'constitution' | 'lifetime' | 'not-yet-valid' | 'expired'
  | 'wrong-org' | 'key-binding' | 'pq-missing' | 'signature' | 'rollback' | 'equivocation';

export type OrgVerifyResult = { ok: true; list: OrgMemberList } | { ok: false; reason: OrgRefusal };

const HEX64 = /^[0-9a-f]{64}$/;
const ISO_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const KEYS = ['constitution_ref', 'expires_at', 'issued_at', 'members', 'org_fp', 'seq', 'v'];

function isoMs(s: unknown): number | null {
  if (typeof s !== 'string' || !ISO_SECONDS.test(s)) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) && new Date(t).toISOString().replace('.000Z', 'Z') === s ? t : null;
}

export function orgMemberListSigningInput(list: OrgMemberList): string {
  return canonicalize(list, { exclude: ['signature', 'pq_signature'] });
}

/** Structural check of an UNSIGNED list. Pure; never throws. */
export function checkOrgMemberListShape(x: unknown): OrgRefusal | null {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return 'shape';
  const o = x as Record<string, unknown>;
  const k = Object.keys(o).sort();
  if (k.length !== KEYS.length || !k.every((y, i) => y === KEYS[i])) return 'shape';
  if (o.v !== ORG_LIST_VERSION) return 'shape';
  if (typeof o.org_fp !== 'string' || !HEX64.test(o.org_fp)) return 'shape';
  if (typeof o.seq !== 'number' || !Number.isSafeInteger(o.seq) || o.seq < 1) return 'shape';
  const issued = isoMs(o.issued_at);
  const expires = isoMs(o.expires_at);
  if (issued === null || expires === null) return 'shape';
  if (!Array.isArray(o.members) || o.members.length > ORG_LIST_MAX_MEMBERS) return 'shape';
  let prev = '';
  for (const m of o.members) {
    if (typeof m !== 'string' || !HEX64.test(m) || m <= prev) return 'shape'; // strictly ascending = sorted, no duplicates
    prev = m;
  }
  if (typeof o.constitution_ref !== 'string') return 'shape';
  if (o.constitution_ref !== '') return 'constitution';                      // v0 can't check one: refuse, never ignore
  if (expires <= issued || expires - issued > ORG_LIST_MAX_LIFETIME_MS) return 'lifetime';
  return null;
}

/** Sign in the PRINCIPAL's app only (O1). Refuses (throws) on a malformed list or without the PQ secret. */
export async function signOrgMemberList(
  list: OrgMemberList,
  orgPrivateKeyArmored: string,
  orgPassphrase: string,
  orgPqSigningSecretKey: Uint8Array,
): Promise<SignedOrgMemberList> {
  const bad = checkOrgMemberListShape(list);
  if (bad) throw new Error(`org member list refused before signing: ${bad}`);
  if (!(orgPqSigningSecretKey instanceof Uint8Array) || orgPqSigningSecretKey.length === 0) {
    throw new Error('org member list refused before signing: the PQ signing key is required (hybrid only)');
  }
  const sig = await signWithEnvelope(
    DOMAIN_ORG_MEMBER_LIST, orgMemberListSigningInput(list), orgPrivateKeyArmored, orgPassphrase, orgPqSigningSecretKey,
  );
  if (!sig.pq_signature) throw new Error('org member list: signer returned no PQ leg');
  return { ...list, signature: sig.classical, pq_signature: sig.pq_signature };
}

/** Verify against the org key the holder already has (an admitted org contact). Never throws. */
export async function verifyOrgMemberList(signed: unknown, org: OrgPublicKeys, now: Date): Promise<OrgVerifyResult> {
  try {
    if (typeof signed !== 'object' || signed === null || Array.isArray(signed)) return { ok: false, reason: 'shape' };
    const { signature, pq_signature, ...rest } = signed as Record<string, unknown>;
    const bad = checkOrgMemberListShape(rest);
    if (bad) return { ok: false, reason: bad };
    const list = rest as unknown as OrgMemberList;
    const t = now.getTime();
    if (isoMs(list.issued_at)! > t + ORG_LIST_CLOCK_SKEW_MS) return { ok: false, reason: 'not-yet-valid' };
    if (isoMs(list.expires_at)! <= t) return { ok: false, reason: 'expired' };
    if (list.org_fp !== org.fingerprint) return { ok: false, reason: 'wrong-org' };
    if (!(await fingerprintMatchesKey(org.fingerprint, org.publicKey, {
      kem_public_key: org.kemPublicKeyB64, sig_public_key: org.sigPublicKeyB64,
    }))) return { ok: false, reason: 'key-binding' };
    if (typeof signature !== 'string' || signature.length === 0) return { ok: false, reason: 'signature' };
    if (typeof pq_signature !== 'string' || pq_signature.length === 0) return { ok: false, reason: 'pq-missing' };
    const good = await verifyWithEnvelope(
      DOMAIN_ORG_MEMBER_LIST, orgMemberListSigningInput(list), { classical: signature, pq_signature },
      org.publicKey, base64ToUint8(org.sigPublicKeyB64),
    );
    return good ? { ok: true, list } : { ok: false, reason: 'signature' };
  } catch {
    return { ok: false, reason: 'signature' };
  }
}

/** A holder's decision for an incoming VERIFIED list, given the list it holds for that org. Pure. */
export function applyOrgMemberList(
  held: OrgMemberList | undefined,
  incoming: OrgMemberList,
): { action: 'store'; list: OrgMemberList } | { action: 'keep' } | { action: 'refuse'; reason: OrgRefusal } {
  if (held && held.org_fp !== incoming.org_fp) return { action: 'refuse', reason: 'wrong-org' };
  if (!held || incoming.seq > held.seq) return { action: 'store', list: incoming };
  if (incoming.seq < held.seq) return { action: 'refuse', reason: 'rollback' };
  return orgMemberListSigningInput(incoming) === orgMemberListSigningInput(held)
    ? { action: 'keep' }
    : { action: 'refuse', reason: 'equivocation' };
}

/**
 * What a holder may show on a card, from the list it holds:
 *  - { status: 'member', as_of: issued_at }            → "Member of <org> (as of <date>)"
 *  - { status: 'list-expired', as_of: expires_at }     → "Can't confirm membership of <org>: its member list expired on <date>."
 *                                                        (NOT a removal: the org may still list them)
 *  - null                                              → nothing (never listed, or removed in a later seq)
 */
export function membershipOf(
  held: OrgMemberList | undefined,
  cardSha: string,
  now: Date,
): { org_fp: string; status: 'member' | 'list-expired'; as_of: string } | null {
  if (!held || !held.members.includes(cardSha)) return null;
  const exp = isoMs(held.expires_at);
  if (exp === null) return null;
  return exp <= now.getTime()
    ? { org_fp: held.org_fp, status: 'list-expired', as_of: held.expires_at }
    : { org_fp: held.org_fp, status: 'member', as_of: held.issued_at };
}
