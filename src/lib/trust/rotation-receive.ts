// src/lib/trust/rotation-receive.ts — task #810 step 1: the ONE receive function for pointers and key-rotation successors.
/**
 * PURE and DARK. No storage, no clock read (`nowMs` is a parameter), no network, no randomness; nothing imports this module yet.
 *
 * Input: what the receiver HOLDS for one contact (HeldIdentity) and one incoming object (bytes). Output: a Decision. Every decision that
 * changes anything carries the COMPLETE next HeldIdentity, so the wiring can write it in ONE persist; a decision that changes nothing carries
 * no `next`. The input is never modified.
 *
 * Rules (RotSign contract R6/R7, relay-move v1.4 R1-R3 and the contested-change rule, #721 design v3.2 D3a):
 *  - Everything is VERIFIED FIRST. Pointers verify against the identity keys the receiver HOLDS, never keys read from the pointer.
 *  - A successor at the held epoch + 1 is ADOPTED at once (R6.4); at or below the held epoch it is STALE (closed, benign); above +1 it is
 *    HELD (the wiring leaves it unacked for retry; nothing is stored). An epoch is never skipped.
 *  - The existing successor verifier is given the DURABLE id as `fingerprint` (it compares successor.durable_id with it), never the
 *    operational fingerprint: otherwise the second rotation of a contact fails (R7.3).
 *  - A pointer at a lower identity epoch is stale; at the held epoch the pointer epoch decides: lower = stale, equal and same claim =
 *    idempotent accept, equal and a different claim = CONFLICT, higher = accept if authority-signed, or if identity-only no further than
 *    held + 16 + A (A = min(64, whole weeks since the contact last accepted, on the CONTACT's own clock, computed fresh, never stored).
 *  - An identity-only pointer may not name a relay other than the held one. An authority-signed one may, but this function never applies a
 *    relay change: it records it as PENDING with `windowRequired` (relay-move rule 4's window is not built).
 *  - Two different valid POINTER claims at one epoch = CONFLICT: adopt neither, no resolution by arrival order or by time. While such a
 *    conflict is open no pointer is accepted (a successor still is: the owner's escape must not be lockable). It is settled only by a local
 *    choice (`settleDigest`); APPROVE and a quorum Stop have no wire form yet.
 *  - A second, DIFFERENT valid successor for the epoch just adopted proves two parties hold the master: recorded as a conflict (kind
 *    'successor', both digests) WITHOUT un-adopting, and nothing freezes (detection, not resolution; Flint #7291). The same claim again,
 *    or re-signed, is a stale duplicate. Only the most recently adopted epoch is checked: older ones are stale.
 *  - The digest of an object is the hash of its SIGNED CLAIM (pointer: the signed prefix; successor: the canonical rotation signing input),
 *    not of its bytes: ML-DSA signatures are randomized, so a re-signed identical claim must not look like a different object.
 *  - `pending` is bounded (PENDING_MAX_KEYS) and refuses the newest when full; it never evicts (an eviction would let junk push a real
 *    object out). Only AUTHORITY-signed claims ever enter it, so a thief holding the identity key alone cannot fill it.
 *  - A refusal carries a reason code only, never any part of the input.
 */
import { parsePointerV2, type VerifiedPointerV2 } from './pointer-v2-wire';
import { parseKeyRotate } from './key-rotate-wire';
import { parseApprove, type VerifiedApprove } from './approve-wire';
import { digestOfPointer, digestOfSuccessor } from './claim-digest';
import type { AdoptedRotationIdentity, KnownContactIdentity } from './contact-update';
import { canonicalPubsFromArmoredPublicKey } from '../identity/fingerprint';

export { digestOfPointer, digestOfSuccessor };

export const POINTER_CEILING_STEP = 16;
export const POINTER_ALLOWANCE_WEEKS_MAX = 64;
export const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
/** Bound of `pending` (a bound, not a protocol constant). A key holds ONE digest: a second different valid one is a conflict, not a second entry. */
export const PENDING_MAX_KEYS = 8;
/** Most digests kept in one SUCCESSOR conflict (the adopted claim plus later different ones): evidence is appended, never replaced. */
export const SUCCESSOR_CONFLICT_MAX_DIGESTS = 4;

export type PendingKind = 'pointer' | 'successor';

export interface PendingEntry {
  readonly kind: PendingKind;
  readonly identityEpoch: number;
  readonly epoch: number;
  /** Digests of VALID claims seen at this key, first seen first. */
  readonly digests: readonly string[];
  /** The contact's OWN clock when the first one was seen. Never read from an object. */
  readonly firstSeenAtMs: number;
}

export interface ConflictState {
  readonly kind: PendingKind;
  readonly identityEpoch: number;
  readonly epoch: number;
  readonly digests: readonly string[];
}

export interface LastAdopted {
  readonly epoch: number;
  /** Digest of the successor that produced the held epoch. */
  readonly digest: string;
  /** The pin that successor was verified against (the one before the held pin). */
  readonly priorPin: string;
}

export interface HeldIdentity {
  /** The DID anchor hex: never changes. */
  readonly durableId: string;
  /** The ADOPTED identity epoch. */
  readonly identityEpoch: number;
  /** The ADOPTED identity public keys (raw Ed25519 32 B, ML-DSA-87 2592 B). Pointers verify against these. */
  readonly identityKeys: { readonly edPublic: Uint8Array; readonly dsaPublic: Uint8Array };
  /** Hash of the CURRENT keys. */
  readonly operationalFingerprint: string;
  readonly classicalPublicKeyArmored: string;
  /** The pin for the NEXT rotation successor (64 hex). Empty = fail closed. */
  readonly rotationPin: string;
  /** The owner-authority commitment (ownerAuthorityCommitment), if the card carried one. */
  readonly ownerAuthorityPin?: string;
  /** null = no pointer held yet. */
  readonly pointerEpoch: number | null;
  readonly heldPointerDigest?: string;
  /** The canonical relay origin the contact is held on. */
  readonly relay: string;
  /** The contact's own clock at the last accept; null = never. */
  readonly lastAcceptedAtMs: number | null;
  readonly pending: readonly PendingEntry[];
  /** Open conflicts: at most one per kind. */
  readonly conflicts: readonly ConflictState[];
  readonly lastAdopted: LastAdopted | null;
  /** Set on adopt (R8.1); the pair-secret consumers clear it. */
  readonly rekeyPending: boolean;
}

export type IncomingKind = 'pointer' | 'successor' | 'approve';
export interface Incoming { readonly kind: IncomingKind; readonly bytes: Uint8Array }
export interface ReceiveOptions {
  /** A conflict is settled by the receiver's own choice of ONE claim: pass its digest and deliver that object again. */
  readonly settleDigest?: string;
}

export type Decision =
  | { readonly action: 'adopt'; readonly kind: 'successor'; readonly digest: string; readonly adopted: AdoptedRotationIdentity; readonly next: HeldIdentity }
  | { readonly action: 'accept'; readonly kind: 'pointer'; readonly digest: string; readonly pointer: VerifiedPointerV2; readonly idempotent: boolean; readonly next?: HeldIdentity }
  | { readonly action: 'pend'; readonly kind: 'pointer'; readonly digest: string; readonly pointer: VerifiedPointerV2; readonly windowRequired: true; readonly relayChange: { readonly from: string; readonly to: string }; readonly next?: HeldIdentity }
  | { readonly action: 'approved'; readonly kind: 'pointer'; readonly digest: string; readonly pointer: VerifiedPointerV2; readonly idempotent: boolean; readonly relayChange?: { readonly from: string; readonly to: string }; readonly next?: HeldIdentity }
  | { readonly action: 'hold'; readonly reason: 'successor-ahead' | 'approve-ahead' }
  | { readonly action: 'stale'; readonly reason: 'stale-successor' | 'stale-identity-epoch' | 'stale-pointer' }
  | { readonly action: 'conflict'; readonly next: HeldIdentity }
  | { readonly action: 'refuse'; readonly reason: string };

const refuse = (reason: string): Decision => Object.freeze({ action: 'refuse', reason });
const HEX64 = /^[0-9a-f]{64}$/;
const isEpoch = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;

/** Whole weeks since the contact last accepted, clamped. A clock that went backward, or no accept yet, gives 0. */
export function pointerAllowance(lastAcceptedAtMs: number | null, nowMs: number): number {
  if (lastAcceptedAtMs === null || nowMs <= lastAcceptedAtMs) return 0;
  return Math.min(POINTER_ALLOWANCE_WEEKS_MAX, Math.floor((nowMs - lastAcceptedAtMs) / WEEK_MS));
}

/** Record a valid claim at (kind, identityEpoch, epoch). 'conflict' = a DIFFERENT valid claim is already there. 'full' = a bound was hit. */
function pendingAdd(held: HeldIdentity, kind: PendingKind, identityEpoch: number, epoch: number, digest: string, nowMs: number):
  { readonly r: 'added'; readonly pending: readonly PendingEntry[] } | { readonly r: 'seen' } | { readonly r: 'conflict'; readonly digests: readonly string[] } | { readonly r: 'full' } {
  const i = held.pending.findIndex((e) => e.kind === kind && e.identityEpoch === identityEpoch && e.epoch === epoch);
  if (i >= 0) {
    const e = held.pending[i];
    if (e.digests.includes(digest)) return e.digests.length > 1 ? { r: 'conflict', digests: e.digests } : { r: 'seen' };
    return { r: 'conflict', digests: [...e.digests, digest] };
  }
  if (held.pending.length >= PENDING_MAX_KEYS) return { r: 'full' };
  return { r: 'added', pending: Object.freeze([...held.pending, Object.freeze({ kind, identityEpoch, epoch, digests: Object.freeze([digest]), firstSeenAtMs: nowMs })]) };
}

const without = (held: HeldIdentity, patch: Partial<{ -readonly [K in keyof HeldIdentity]: HeldIdentity[K] }>): HeldIdentity => Object.freeze({ ...held, ...patch });

function checkHeld(h: HeldIdentity): string | null {
  if (!h || typeof h !== 'object') return 'bad-held';
  if (!HEX64.test(h.durableId) || !isEpoch(h.identityEpoch)) return 'bad-held';
  if (!(h.identityKeys?.edPublic instanceof Uint8Array) || h.identityKeys.edPublic.length !== 32) return 'bad-held';
  if (!(h.identityKeys?.dsaPublic instanceof Uint8Array) || h.identityKeys.dsaPublic.length !== 2592) return 'bad-held';
  if (h.pointerEpoch !== null && !isEpoch(h.pointerEpoch)) return 'bad-held';
  if (h.ownerAuthorityPin !== undefined && !HEX64.test(h.ownerAuthorityPin)) return 'bad-held';
  if (!Array.isArray(h.conflicts) || !Array.isArray(h.pending)) return 'bad-held';
  return null;
}

export async function receive(held: HeldIdentity, incoming: Incoming, nowMs: number, opts: ReceiveOptions = {}): Promise<Decision> {
  try {
    const bad = checkHeld(held);
    if (bad) return refuse(bad);
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) return refuse('bad-now');
    if (!(incoming?.bytes instanceof Uint8Array)) return refuse('bad-input');
    if (incoming.kind === 'successor') return await receiveSuccessor(held, incoming.bytes, nowMs, opts);
    if (incoming.kind === 'pointer') return receivePointer(held, incoming.bytes, nowMs, opts);
    if (incoming.kind === 'approve') return receiveApprove(held, incoming.bytes, nowMs);
    return refuse('bad-kind');
  } catch {
    return refuse('receive-failed'); // never a part of the input
  }
}

/** While a conflict is open only the receiver's own chosen claim may pass, and only by name. */
function conflictGate(held: HeldIdentity, kind: PendingKind, digest: string | null, opts: ReceiveOptions): Decision | null {
  const c = held.conflicts.find((x) => x.kind === kind);
  if (!c || kind === 'successor') return null; // a successor conflict is detection only: it never freezes anything
  if (digest !== null && opts.settleDigest === digest && c.digests.includes(digest)) return null;
  return refuse('conflict-open');
}
const withConflict = (cs: readonly ConflictState[], c: ConflictState): readonly ConflictState[] => Object.freeze([...cs.filter((x) => x.kind !== c.kind), c]);

async function receiveSuccessor(held: HeldIdentity, bytes: Uint8Array, nowMs: number, opts: ReceiveOptions): Promise<Decision> {
  let parsed;
  try { parsed = parseKeyRotate(bytes); } catch (e) { return refuse('malformed:' + (e && typeof (e as { reason?: unknown }).reason === 'string' ? (e as { reason: string }).reason : 'parse')); }
  // Routing by the claimed epoch (UNVERIFIED; it only picks a branch, and the two branches that skip verify change no state).
  const claimed = parsed.claimedSuccessorEpoch();
  if (!isEpoch(claimed)) return refuse('bad-epoch');
  if (claimed <= held.identityEpoch) {
    const la = held.lastAdopted;
    if (la && claimed === held.identityEpoch && la.epoch === claimed) {
      // The epoch we just adopted. A different VALID claim for it proves a second master holder: record it, never un-adopt.
      const prior: KnownContactIdentity = { fingerprint: held.durableId, epoch: claimed - 1, version: 0, classicalPublicKeyArmored: held.classicalPublicKeyArmored, next_authority_commitment: la.priorPin };
      let pv;
      try { pv = await parsed.verify(prior); } catch { return Object.freeze({ action: 'stale', reason: 'stale-successor' }); }
      const d = digestOfSuccessor(pv.successor, la.priorPin);
      const known = held.conflicts.find((x) => x.kind === 'successor');
      if (d === la.digest || (known && known.digests.includes(d))) return Object.freeze({ action: 'stale', reason: 'stale-successor' });
      const digests = [...(known ? known.digests : [la.digest]), d];
      if (digests.length > SUCCESSOR_CONFLICT_MAX_DIGESTS) return Object.freeze({ action: 'stale', reason: 'stale-successor' }); // evidence is kept, not replaced; past the cap there is nothing more to add
      return Object.freeze({ action: 'conflict', next: without(held, { conflicts: withConflict(held.conflicts, Object.freeze({ kind: 'successor', identityEpoch: claimed, epoch: claimed, digests: Object.freeze(digests) })) }) });
    }
    return Object.freeze({ action: 'stale', reason: 'stale-successor' });
  }
  if (claimed > held.identityEpoch + 1) return Object.freeze({ action: 'hold', reason: 'successor-ahead' });
  const known: KnownContactIdentity = {
    fingerprint: held.durableId, // the DURABLE id, never the operational fingerprint (R7.3)
    epoch: held.identityEpoch,
    version: 0,
    classicalPublicKeyArmored: held.classicalPublicKeyArmored,
    next_authority_commitment: held.rotationPin,
  };
  let v;
  try { v = await parsed.verify(known); } catch (e) { return refuse(e && typeof (e as { reason?: unknown }).reason === 'string' ? (e as { reason: string }).reason : 'verify-failed'); }
  const digest = digestOfSuccessor(v.successor, held.rotationPin);
  const gate = conflictGate(held, 'successor', digest, opts);
  if (gate) return gate;
  const pubs = await canonicalPubsFromArmoredPublicKey(v.successor.new_public_key, v.successor.new_pq_kem_public_key, v.successor.new_pq_sig_public_key);
  const next = Object.freeze({
    ...held,
    identityEpoch: v.adopted.epoch,
    identityKeys: Object.freeze({ edPublic: pubs.signPub.slice(), dsaPublic: pubs.sigPub.slice() }),
    operationalFingerprint: v.adopted.fingerprint,
    classicalPublicKeyArmored: v.adopted.classicalPublicKeyArmored,
    rotationPin: v.adopted.next_authority_commitment,
    pointerEpoch: null,
    heldPointerDigest: undefined,
    lastAcceptedAtMs: nowMs,
    pending: Object.freeze([]),
    conflicts: Object.freeze(held.conflicts.filter((x) => x.kind === 'successor')), // a pointer conflict was about the old keys
    lastAdopted: Object.freeze({ epoch: v.adopted.epoch, digest, priorPin: held.rotationPin }),
    rekeyPending: true,
  }) as HeldIdentity;
  return Object.freeze({ action: 'adopt', kind: 'successor', digest, adopted: v.adopted, next });
}

function receivePointer(held: HeldIdentity, bytes: Uint8Array, nowMs: number, opts: ReceiveOptions): Decision {
  let parsed;
  try { parsed = parsePointerV2(bytes); } catch (e) { return refuse('malformed:' + (e && typeof (e as { reason?: unknown }).reason === 'string' ? (e as { reason: string }).reason : 'parse')); }
  let v: VerifiedPointerV2;
  try {
    v = parsed.verify({ identity: held.identityKeys, authorityPin: held.ownerAuthorityPin });
  } catch (e) {
    // A pointer under keys we do not hold yet fails here (bad-identity-sig). The wiring decides whether to keep it for a retry after an adopt.
    return refuse(e && typeof (e as { reason?: unknown }).reason === 'string' ? (e as { reason: string }).reason : 'verify-failed');
  }
  const digest = digestOfPointer(v);
  const gate = conflictGate(held, 'pointer', digest, opts);
  if (gate) return gate;
  if (v.identityEpoch < held.identityEpoch) return Object.freeze({ action: 'stale', reason: 'stale-identity-epoch' });
  // Signed by the keys we HOLD, yet claiming a higher epoch than the one we adopted: incoherent, never followed.
  if (v.identityEpoch > held.identityEpoch) return refuse('identity-epoch-ahead');
  const e = v.pointerEpoch;
  const h = held.pointerEpoch;
  const settling = held.conflicts.some((x) => x.kind === 'pointer'); // the conflict gate let this object pass: it is the receiver's own choice
  if (h !== null && e < h && !settling) return Object.freeze({ action: 'stale', reason: 'stale-pointer' });
  // Only a claim the receiver could ACCEPT may enter a conflict: an identity-only pointer naming another relay never could.
  if (!v.authoritySigned && v.relay !== held.relay) return refuse('relay-change-needs-authority');
  if (h !== null && e === h && !settling) {
    if (digest === held.heldPointerDigest) return Object.freeze({ action: 'accept', kind: 'pointer', digest, pointer: v, idempotent: true });
    return Object.freeze({ action: 'conflict', next: without(held, { conflicts: withConflict(held.conflicts, Object.freeze({ kind: 'pointer', identityEpoch: v.identityEpoch, epoch: e, digests: Object.freeze([held.heldPointerDigest ?? '', digest].filter((d) => d !== '')) })) }) });
  }
  if (h !== null && e > h && !v.authoritySigned) {
    const ceiling = h + POINTER_CEILING_STEP + pointerAllowance(held.lastAcceptedAtMs, nowMs);
    if (e > ceiling) return refuse('above-ceiling');
  }
  if (h === null && !v.authoritySigned && e > POINTER_CEILING_STEP + pointerAllowance(held.lastAcceptedAtMs, nowMs)) return refuse('above-ceiling');
  if (v.relay !== held.relay) {
    const relayChange = Object.freeze({ from: held.relay, to: v.relay });
    if (settling) {
      // The receiver chose this claim: the conflict ends and the pending entry is RESET to the chosen digest (never left holding both).
      const i = held.pending.findIndex((x) => x.kind === 'pointer' && x.identityEpoch === v.identityEpoch && x.epoch === e);
      const old = i >= 0 ? held.pending[i] : null;
      if (!old && held.pending.length >= PENDING_MAX_KEYS) return refuse('pending-full');
      const entry = Object.freeze({ kind: 'pointer' as const, identityEpoch: v.identityEpoch, epoch: e, digests: Object.freeze([digest]), firstSeenAtMs: old && old.digests[0] === digest ? old.firstSeenAtMs : nowMs });
      const pending = Object.freeze(i >= 0 ? held.pending.map((x, j) => (j === i ? entry : x)) : [...held.pending, entry]);
      return Object.freeze({ action: 'pend', kind: 'pointer', digest, pointer: v, windowRequired: true as const, relayChange, next: without(held, { pending, conflicts: Object.freeze(held.conflicts.filter((x) => x.kind !== 'pointer')) }) });
    }
    const p = pendingAdd(held, 'pointer', v.identityEpoch, e, digest, nowMs);
    if (p.r === 'full') return refuse('pending-full');
    if (p.r === 'conflict') {
      return Object.freeze({ action: 'conflict', next: without(held, { conflicts: withConflict(held.conflicts, Object.freeze({ kind: 'pointer', identityEpoch: v.identityEpoch, epoch: e, digests: Object.freeze([...p.digests]) })) }) });
    }
    return Object.freeze({
      action: 'pend', kind: 'pointer', digest, pointer: v, windowRequired: true as const, relayChange,
      ...(p.r === 'added' ? { next: without(held, { pending: p.pending }) } : {}),
    });
  }
  const next = without(held, {
    pointerEpoch: e,
    heldPointerDigest: digest,
    lastAcceptedAtMs: nowMs,
    // Only an AUTHORITY-signed accept may drop a pending authority-signed move: a lower authority never cancels a higher one.
    pending: v.authoritySigned ? Object.freeze(held.pending.filter((x) => !(x.kind === 'pointer' && x.identityEpoch === v.identityEpoch && x.epoch <= e))) : held.pending,
    conflicts: Object.freeze(held.conflicts.filter((x) => x.kind !== 'pointer')),
  });
  return Object.freeze({ action: 'accept', kind: 'pointer', digest, pointer: v, idempotent: false, next });
}

/**
 * APPROVE (D2 v1.6): one self-contained record carrying the owner-authority AND the identity signatures over a pointer that moves the relay.
 * It is exempt from the conflict gate and from pending-full: it exists to settle and to supersede, so neither a conflict nor a full pending list
 * can lock it out. On success the approved claim is adopted NOW (W waived, the relay change applied); pending attempts and conflicts at or
 * below its epoch are dropped; a pending attempt at a HIGHER epoch stays under its own window; the same record again is a no-op.
 */
function receiveApprove(held: HeldIdentity, bytes: Uint8Array, nowMs: number): Decision {
  let parsed;
  try { parsed = parseApprove(bytes); } catch (e) { return refuse('malformed:' + (e && typeof (e as { reason?: unknown }).reason === 'string' ? (e as { reason: string }).reason : 'parse')); }
  let v: VerifiedApprove;
  try {
    v = parsed.verify({ held: { durableId: held.durableId, identityEpoch: held.identityEpoch, identityKeys: held.identityKeys, ownerAuthorityPin: held.ownerAuthorityPin } });
  } catch (e) {
    const reason = e && typeof (e as { reason?: unknown }).reason === 'string' ? (e as { reason: string }).reason : 'verify-failed';
    if (reason === 'stale-identity-epoch') return Object.freeze({ action: 'stale', reason: 'stale-identity-epoch' });
    if (reason === 'identity-epoch-ahead') return Object.freeze({ action: 'hold', reason: 'approve-ahead' }); // keys we do not hold yet: write nothing
    return refuse(reason);
  }
  const p = v.pointer;
  const e = p.pointerEpoch;
  const h = held.pointerEpoch;
  if (h !== null && e < h) return Object.freeze({ action: 'stale', reason: 'stale-pointer' });
  if (h !== null && e === h && v.claimDigest === held.heldPointerDigest) return Object.freeze({ action: 'approved', kind: 'pointer', digest: v.claimDigest, pointer: p, idempotent: true });
  const relayChange = p.relay !== held.relay ? Object.freeze({ from: held.relay, to: p.relay }) : undefined;
  const next = without(held, {
    pointerEpoch: e,
    heldPointerDigest: v.claimDigest,
    relay: p.relay,
    lastAcceptedAtMs: nowMs,
    pending: Object.freeze(held.pending.filter((x) => !(x.kind === 'pointer' && x.identityEpoch === v.identityEpoch && x.epoch <= e))),
    conflicts: Object.freeze(held.conflicts.filter((x) => !(x.kind === 'pointer' && x.identityEpoch === v.identityEpoch && x.epoch <= e))),
  });
  return Object.freeze({ action: 'approved', kind: 'pointer', digest: v.claimDigest, pointer: p, idempotent: false, ...(relayChange ? { relayChange } : {}), next });
}
