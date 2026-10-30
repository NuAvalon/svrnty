// src/lib/trust/agent-cert.ts
// #705 INT-4: a HUMAN signs one cert SET naming their agents: "these agents are mine, for this scope". Contract:
// shared/outbox/archie/dag_contracts/svrnty_705_introduce_orgs_v2.md (sha256 04e83182…), V1–V6 per Flint task:705 #1494.
//
// WHAT IT SAYS. {v, human_fp, seq, issued_at, expires_at, agents:[{agent_card_sha256, agent_fp, scope}]}. One set per
// human, one monotonic seq. Revoking an agent = a new set with a HIGHER seq that leaves it out (V3); an older set can
// never come back (the TM1 downgrade pattern), and two different sets at the same seq are equivocation → refused.
// WHAT IT NEVER SAYS (V1, V4). Not "act as me": the scope is a closed enum with no principal-level value, and the
// domain tag is its own, so a cert signature can never verify as a vouch, card, signal or rotation. An agent cert gives
// the agent NO authority of its human's; whoever displays it may say "<agent>, agent of <human>" and nothing more.
// SIGNATURE. Hybrid ALWAYS (classical + ML-DSA-87): a cert is a long-lived key statement (Peter's signature policy:
// long-lived = hybrid). The verifier REQUIRES the PQ leg and passes the human's PQ key itself (Flint F-PQ1: never
// inherit a verifier that drops it). Every identity is canonical (fingerprintMatchesKey is canonical-only).
// CUSTODY (V6). This module handles PUBLIC cards + certs only. It never takes, stores or derives an agent's secret.
// STATUS. Library only: nothing in the app calls it yet (no UI, no wire). A display or transport caller is a later
// change with its own review.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize } from '../format/canonical';
import { DOMAIN_AGENT_CERT_SET } from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope } from '../crypto/sign-envelope';
import { base64ToUint8 } from '../crypto/pq';
import { fingerprintMatchesKey } from '../identity/fingerprint';
import type { SignedIdentityCard } from '../identity/identity-card-sign';

/** The ONLY scopes. Nothing here means "act as me" / admin / principal (V1); unknown → refused. */
export const AGENT_CERT_SCOPES = ['collaborate', 'read-only'] as const;
export type AgentCertScope = (typeof AGENT_CERT_SCOPES)[number];

export const AGENT_CERT_VERSION = 1;
/** Bounded so a set (and anything that pads to it) stays small. */
export const AGENT_CERT_MAX_AGENTS = 64;
/** A cert set lives at most this long; a human re-signs to extend. */
export const AGENT_CERT_MAX_LIFETIME_MS = 400 * 24 * 3600 * 1000;
/** How far in the future issued_at may be (clock skew between the human's device and a holder). */
export const AGENT_CERT_CLOCK_SKEW_MS = 5 * 60 * 1000;

export interface AgentCertEntry {
  agent_card_sha256: string; // 64 lowercase hex: agentCardSha256(the agent's signed card)
  agent_fp: string;          // 64 lowercase hex: the agent's canonical fingerprint
  scope: AgentCertScope;
}

export interface AgentCertSet {
  v: number;                 // AGENT_CERT_VERSION
  human_fp: string;          // 64 lowercase hex: the signing human's canonical fingerprint
  seq: number;               // monotonic per human, ≥ 1
  issued_at: string;         // YYYY-MM-DDTHH:MM:SSZ
  expires_at: string;        // YYYY-MM-DDTHH:MM:SSZ
  agents: AgentCertEntry[];  // strictly ascending by agent_fp (one encoding, no duplicates)
}

export interface SignedAgentCertSet extends AgentCertSet {
  signature: string;         // classical
  pq_signature: string;      // ML-DSA-87, REQUIRED
}

/** The human key a holder already has for human_fp (from an admitted contact): public material only. */
export interface HumanPublicKeys {
  fingerprint: string;
  publicKey: string;         // armored classical
  kemPublicKeyB64: string;
  sigPublicKeyB64: string;   // ML-DSA-87 public
}

export type CertRefusal =
  | 'shape'            // anything not exactly the schema (unknown key, bad type, bad hex, unsorted, duplicate)
  | 'scope'            // a scope outside AGENT_CERT_SCOPES
  | 'self'             // an agent_fp equal to the human_fp (a human can't be their own agent)
  | 'lifetime'         // expires before issued, or longer than AGENT_CERT_MAX_LIFETIME_MS
  | 'not-yet-valid'    // issued_at beyond now + skew
  | 'expired'
  | 'wrong-human'      // human_fp ≠ the key we were given
  | 'key-binding'      // that key doesn't hash to its fingerprint
  | 'pq-missing'       // no PQ leg (hybrid is required)
  | 'signature'
  | 'rollback'         // a lower seq than one already held
  | 'equivocation';    // a different set at a seq already held

export type VerifyResult = { ok: true; set: AgentCertSet } | { ok: false; reason: CertRefusal };

const HEX64 = /^[0-9a-f]{64}$/;
const ISO_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SET_KEYS = ['agents', 'expires_at', 'human_fp', 'issued_at', 'seq', 'v'];
const ENTRY_KEYS = ['agent_card_sha256', 'agent_fp', 'scope'];

function exactKeys(o: unknown, keys: string[]): o is Record<string, unknown> {
  if (typeof o !== 'object' || o === null || Array.isArray(o)) return false;
  const k = Object.keys(o).sort();
  return k.length === keys.length && k.every((x, i) => x === keys[i]);
}

function isoMs(s: unknown): number | null {
  if (typeof s !== 'string' || !ISO_SECONDS.test(s)) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) && new Date(t).toISOString().replace('.000Z', 'Z') === s ? t : null;
}

/** sha256 hex of the agent's WHOLE signed card (signatures included) in canonical form: the exact card, nothing else. */
export function agentCardSha256(card: SignedIdentityCard): string {
  return bytesToHex(sha256(utf8ToBytes(canonicalize(card))));
}

/** The canonical bytes a cert set's signature covers (both signature fields excluded). */
export function agentCertSetSigningInput(set: AgentCertSet): string {
  return canonicalize(set, { exclude: ['signature', 'pq_signature'] });
}

/** Structural check of an UNSIGNED set (the signature fields must already be stripped). Pure; never throws. */
export function checkAgentCertSetShape(x: unknown): CertRefusal | null {
  if (!exactKeys(x, SET_KEYS)) return 'shape';
  if (x.v !== AGENT_CERT_VERSION) return 'shape';
  if (typeof x.human_fp !== 'string' || !HEX64.test(x.human_fp)) return 'shape';
  if (typeof x.seq !== 'number' || !Number.isSafeInteger(x.seq) || x.seq < 1) return 'shape';
  const issued = isoMs(x.issued_at);
  const expires = isoMs(x.expires_at);
  if (issued === null || expires === null) return 'shape';
  if (!Array.isArray(x.agents) || x.agents.length > AGENT_CERT_MAX_AGENTS) return 'shape';
  const cards = new Set<string>();
  let prev = '';
  for (const e of x.agents) {
    if (!exactKeys(e, ENTRY_KEYS)) return 'shape';
    if (typeof e.agent_fp !== 'string' || !HEX64.test(e.agent_fp)) return 'shape';
    if (typeof e.agent_card_sha256 !== 'string' || !HEX64.test(e.agent_card_sha256)) return 'shape';
    if (e.agent_fp <= prev) return 'shape';                          // strictly ascending = sorted + no duplicate fp
    prev = e.agent_fp;
    if (cards.has(e.agent_card_sha256)) return 'shape';              // one card can't be listed twice
    cards.add(e.agent_card_sha256);
    if (!(AGENT_CERT_SCOPES as readonly unknown[]).includes(e.scope)) return 'scope';
    if (e.agent_fp === x.human_fp) return 'self';
  }
  if (expires <= issued || expires - issued > AGENT_CERT_MAX_LIFETIME_MS) return 'lifetime';
  return null;
}

/** Sign a set with the human's keys. Refuses (throws) on a malformed set or without the PQ secret: never a weak cert. */
export async function signAgentCertSet(
  set: AgentCertSet,
  humanPrivateKeyArmored: string,
  humanPassphrase: string,
  humanPqSigningSecretKey: Uint8Array,
): Promise<SignedAgentCertSet> {
  const bad = checkAgentCertSetShape(set);
  if (bad) throw new Error(`agent cert set refused before signing: ${bad}`);
  if (!(humanPqSigningSecretKey instanceof Uint8Array) || humanPqSigningSecretKey.length === 0) {
    throw new Error('agent cert set refused before signing: the PQ signing key is required (hybrid only)');
  }
  const sig = await signWithEnvelope(
    DOMAIN_AGENT_CERT_SET, agentCertSetSigningInput(set), humanPrivateKeyArmored, humanPassphrase, humanPqSigningSecretKey,
  );
  if (!sig.pq_signature) throw new Error('agent cert set: signer returned no PQ leg');
  return { ...set, signature: sig.classical, pq_signature: sig.pq_signature };
}

/**
 * Verify a signed set against the human key the holder ALREADY has (from an admitted contact). Never throws.
 * Order: shape → time → key binding → PQ leg present → hybrid signature with the human's own PQ key.
 */
export async function verifyAgentCertSet(signed: unknown, human: HumanPublicKeys, now: Date): Promise<VerifyResult> {
  try {
    if (typeof signed !== 'object' || signed === null || Array.isArray(signed)) return { ok: false, reason: 'shape' };
    const { signature, pq_signature, ...rest } = signed as Record<string, unknown>;
    const bad = checkAgentCertSetShape(rest);
    if (bad) return { ok: false, reason: bad };
    const set = rest as unknown as AgentCertSet;
    const t = now.getTime();
    if (isoMs(set.issued_at)! > t + AGENT_CERT_CLOCK_SKEW_MS) return { ok: false, reason: 'not-yet-valid' };
    if (isoMs(set.expires_at)! <= t) return { ok: false, reason: 'expired' };
    if (set.human_fp !== human.fingerprint) return { ok: false, reason: 'wrong-human' };
    if (!(await fingerprintMatchesKey(human.fingerprint, human.publicKey, {
      kem_public_key: human.kemPublicKeyB64, sig_public_key: human.sigPublicKeyB64,
    }))) return { ok: false, reason: 'key-binding' };
    if (typeof signature !== 'string' || signature.length === 0) return { ok: false, reason: 'signature' };
    if (typeof pq_signature !== 'string' || pq_signature.length === 0) return { ok: false, reason: 'pq-missing' };
    const good = await verifyWithEnvelope(
      DOMAIN_AGENT_CERT_SET, agentCertSetSigningInput(set), { classical: signature, pq_signature },
      human.publicKey, base64ToUint8(human.sigPublicKeyB64),
    );
    return good ? { ok: true, set } : { ok: false, reason: 'signature' };
  } catch {
    return { ok: false, reason: 'signature' };
  }
}

/**
 * A holder's decision for an incoming VERIFIED set, given the set it already holds for that human (if any). Pure.
 * Higher seq replaces; lower seq is a rollback; the same seq is a no-op only if it is the same set.
 */
export function applyAgentCertSet(
  held: AgentCertSet | undefined,
  incoming: AgentCertSet,
): { action: 'store'; set: AgentCertSet } | { action: 'keep' } | { action: 'refuse'; reason: CertRefusal } {
  if (held && held.human_fp !== incoming.human_fp) return { action: 'refuse', reason: 'wrong-human' };
  if (!held || incoming.seq > held.seq) return { action: 'store', set: incoming };
  if (incoming.seq < held.seq) return { action: 'refuse', reason: 'rollback' };
  return agentCertSetSigningInput(incoming) === agentCertSetSigningInput(held)
    ? { action: 'keep' }
    : { action: 'refuse', reason: 'equivocation' };
}

/**
 * "<agent>, agent of <human>" is shown ONLY when this returns non-null: the held set is unexpired and lists exactly this
 * agent fp WITH exactly this card. Anything else (expired, removed, a different card for the same fp) → null.
 */
export function agentOf(
  held: AgentCertSet | undefined,
  agentFp: string,
  agentCardSha: string,
  now: Date,
): { human_fp: string; scope: AgentCertScope; seq: number } | null {
  if (!held) return null;
  const exp = isoMs(held.expires_at);
  if (exp === null || exp <= now.getTime()) return null;
  const e = held.agents.find((x) => x.agent_fp === agentFp);
  if (!e || e.agent_card_sha256 !== agentCardSha) return null;
  return { human_fp: held.human_fp, scope: e.scope, seq: held.seq };
}

/** A cert entry binds a card only if the card is an attested AGENT card with that fp and that exact hash. */
export function entryCoversCard(entry: AgentCertEntry, card: SignedIdentityCard): boolean {
  return card?.entity_type === 'agent'
    && card.identity?.fingerprint === entry.agent_fp
    && agentCardSha256(card) === entry.agent_card_sha256;
}
