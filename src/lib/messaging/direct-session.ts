// 1:1 notes → TripleRatchet. Calls the fleet ratchet; does not reimplement KDF / DH / KEM.
//
// OpenPGP still wraps the mailbox blob (existing deposit). The inner body is a ratchet
// packet when both sides have X25519 + ML-KEM. Legacy plaintext bodies stay accepted.
// isPQEncapLive() stays false until Flint flips it. Do not market this as Signal-grade.

import { TripleRatchet, type RatchetIdentity, type RatchetPacket, type RatchetPeer, type RatchetSnapshot } from '@/lib/crypto/message-ratchet';
import { readRatchetSession, putRatchetSession, notesStoreOwner, type RatchetSessionRead } from './store';
import { assertNotesStoreOpenFor } from './notes-owner-guard';
import { acquirePeerSessionLock, peerSessionLockName, type LockRelease } from './peer-session-lock';

export const TRIPLE_RATCHET_BODY = 'svrnty-tr-v1';

export type TripleRatchetBody = {
  type: typeof TRIPLE_RATCHET_BODY;
  packet: RatchetPacket;
};

export function isTripleRatchetBody(body: string): boolean {
  try {
    const o = JSON.parse(body) as Partial<TripleRatchetBody>;
    return o?.type === TRIPLE_RATCHET_BODY && !!o.packet && typeof o.packet === 'object';
  } catch {
    return false;
  }
}

function encodeBody(packet: RatchetPacket): string {
  const wire: TripleRatchetBody = { type: TRIPLE_RATCHET_BODY, packet };
  return JSON.stringify(wire);
}

function decodeBody(body: string): RatchetPacket | null {
  try {
    const o = JSON.parse(body) as TripleRatchetBody;
    if (o?.type !== TRIPLE_RATCHET_BODY || !o.packet) return null;
    return o.packet;
  } catch {
    return null;
  }
}

/**
 * The ratchet-session persistence the policy below depends on. Injectable so the stateful behaviour (what is read, what is
 * written, in what order) is testable with REAL ratchet crypto and no IndexedDB. Defaults to the real encrypted store.
 */
export interface RatchetIO {
  read: (peerFingerprint: string) => Promise<RatchetSessionRead>;
  /** CAS write (R5): succeeds only if the stored row is still at `expectedVersion` (0 = no row yet); otherwise throws RatchetSessionConflictError. */
  put: (peerFingerprint: string, snapshot: RatchetSnapshot, expectedVersion: number) => Promise<void>;
  /** Who the session store is open for; scopes the per-peer lock name so two identities never block each other. */
  scope?: string;
  /** Test seam: replaces the real per-peer lock. Production leaves it unset and gets navigator.locks (or the in-process queue). */
  acquireLock?: (peerFingerprint: string) => Promise<LockRelease>;
}

/** Take the exclusive per-peer session lock (R5). Held across load -> advance -> persist; the caller MUST release it. */
function lockSession(io: RatchetIO, peerFingerprint: string): Promise<LockRelease> {
  return io.acquireLock ? io.acquireLock(peerFingerprint) : acquirePeerSessionLock(peerSessionLockName(io.scope, peerFingerprint));
}
/** The raw store handle, with NO owner check. Production code never uses it directly: it goes through {@link ownerBoundRatchetIO}. */
export const realRatchetIO: RatchetIO = { read: readRatchetSession, put: putRatchetSession };

/**
 * R2: the session store is tab-local module state, open for ONE identity. Bind every session read AND write to the owner the
 * caller is acting for: if the store is locked or open for a different identity (a cross-tab switch), the operation THROWS before
 * touching anything, so a wrong-owner open can never advance, create or overwrite a session. A throw is load-bearing: send fails
 * closed, and the receive path maps it to RETRYABLE (the note stays in the mailbox for a later retry, within the relay's hold,
 * instead of being dropped here).
 */
export function ownerBoundRatchetIO(
  ownerFingerprint: string,
  openOwner: () => string | null = notesStoreOwner,
  inner: RatchetIO = realRatchetIO,
): RatchetIO {
  return {
    read: async (peerFp) => { assertNotesStoreOpenFor(openOwner(), ownerFingerprint); return inner.read(peerFp); },
    put: async (peerFp, snapshot, expectedVersion) => { assertNotesStoreOpenFor(openOwner(), ownerFingerprint); return inner.put(peerFp, snapshot, expectedVersion); },
    scope: ownerFingerprint,
    acquireLock: inner.acquireLock,
  };
}

/** A session row exists for this peer but cannot be read. Never treated as "no session" (R3). */
export class RatchetSessionUnreadableError extends Error {
  constructor() {
    super('ratchet session unreadable: refusing to start a parallel session over it');
    this.name = 'RatchetSessionUnreadableError';
  }
}

/**
 * D1, observed capability: we ratchet to a peer ONLY after we have successfully OPENED a ratchet frame from them. A peer that
 * cannot read triple-ratchet frames (our headless agents, an older client) leaves frames it cannot open sitting unread, so we
 * never start a ratchet "at" a peer on a guess. The signal is already in the session: `recvCk` is null on an initiator-only
 * session (TripleRatchet.initiate) and set once a frame from the peer has been received and opened (acceptFirst / receive).
 * Absent session => not observed. Unreadable session => throws (we cannot tell; do not guess either way).
 */
export async function ratchetCapabilityObserved(peerFingerprint: string, io: RatchetIO = realRatchetIO): Promise<boolean> {
  const cur = await io.read(peerFingerprint);
  if (cur.state === 'unreadable') throw new RatchetSessionUnreadableError();
  return cur.state === 'ok' && cur.snapshot.recvCk !== null;
}

/** Seal plaintext for one peer. Persists the session (CAS on the version it read). The CALLER holds the per-peer lock (R5); see chooseWireBody. Null if the ratchet cannot start. */
export async function sealDirectNote(
  peerFingerprint: string,
  plaintext: string,
  self: RatchetIdentity,
  peer: RatchetPeer,
  io: RatchetIO = realRatchetIO,
): Promise<string | null> {
  const cur = await io.read(peerFingerprint);
  if (cur.state === 'unreadable') return null; // R3: a row exists but cannot be read: fail closed, never start a parallel session over it
  let session = cur.state === 'ok' ? TripleRatchet.importState(cur.snapshot) : null;
  if (!session) {
    if (cur.state === 'ok') return null; // corrupt snapshot — fail closed, do not mint a parallel session
    session = TripleRatchet.initiate(self, peer);
  }
  const packet = await session.send(plaintext);
  await io.put(peerFingerprint, session.exportState(), cur.state === 'ok' ? cur.version : 0);
  return encodeBody(packet);
}

/**
 * An opened ratchet message whose session advance has NOT been persisted yet. R4: the advanced session is committed only AFTER the
 * note it carried is durably stored. Otherwise a store failure after the open leaves the envelope retryable but the session already
 * moved past that message key, so the retry cannot open it (receive() returns null) and the message is lost although the relay still
 * held it.
 *
 * R5: a StagedOpen HOLDS the per-peer session lock from the read until it is finished, because commit() is the write half of a
 * read-modify-write. Exactly one of commit() / release() ends it, and both release the lock (idempotent). commit() writes with a CAS
 * on the version that was read; if another context moved the session meanwhile it throws RatchetSessionConflictError, nothing is
 * written, and the envelope stays retryable.
 */
export interface StagedOpen {
  plaintext: string;
  commit: () => Promise<void>;
  /** Give the lock back without committing (the note was not stored). Safe to call after commit() and more than once. */
  release: () => void;
}

/** Open a ratchet body from one peer WITHOUT persisting the advanced session; the caller commits once the note is stored (R4) and MUST end the StagedOpen (commit or release) so the lock is freed (R5). */
export async function openDirectNoteStaged(
  peerFingerprint: string,
  body: string,
  self: RatchetIdentity,
  peer: RatchetPeer,
  io: RatchetIO = realRatchetIO,
): Promise<StagedOpen | null> {
  const packet = decodeBody(body);
  if (!packet) return null;
  const unlock = await lockSession(io, peerFingerprint);
  let handedOver = false;
  try {
    const cur = await io.read(peerFingerprint);
    if (cur.state === 'unreadable') return null; // R3: never acceptFirst over an unreadable row (it would overwrite the real session)
    let plaintext: string;
    let next: RatchetSnapshot;
    if (cur.state === 'ok') {
      const session = TripleRatchet.importState(cur.snapshot);
      if (!session) return null;
      const pt = await session.receive(packet);
      if (pt === null) return null;
      plaintext = pt;
      next = session.exportState();
    } else {
      const first = await TripleRatchet.acceptFirst(self, peer, packet);
      if (!first) return null;
      plaintext = first.plaintext;
      next = first.session.exportState();
    }
    const expected = cur.state === 'ok' ? cur.version : 0;
    let ended = false;
    const release = () => { if (!ended) { ended = true; unlock(); } };
    handedOver = true;
    return {
      plaintext,
      release,
      commit: async () => {
        if (ended) throw new Error('staged ratchet open already ended');
        try { await io.put(peerFingerprint, next, expected); } finally { release(); }
      },
    };
  } finally {
    if (!handedOver) unlock();
  }
}

/** Open a ratchet body from one peer and persist the session immediately. Null on tamper / missing keys. Kept for callers that have nothing to store. */
export async function openDirectNote(
  peerFingerprint: string,
  body: string,
  self: RatchetIdentity,
  peer: RatchetPeer,
  io: RatchetIO = realRatchetIO,
): Promise<string | null> {
  const staged = await openDirectNoteStaged(peerFingerprint, body, self, peer, io);
  if (!staged) return null;
  await staged.commit();
  return staged.plaintext;
}

/**
 * The SEND-side wire-body policy, in the only order that is safe (R1): gate -> ratchet -> sign -> seal -> POST.
 *  1. If the note cannot be deposited (no verified ML-KEM key, fail-closed) NOTHING stateful happens: no session is read,
 *     created or advanced. (Before this, the ratchet advanced and persisted first, so a send to a keyless peer burned an index
 *     and deposited nothing.)
 *  2. Otherwise ratchet only to a peer whose capability we have OBSERVED (D1); anyone else gets the plain body, which still
 *     travels inside the hybrid outer seal, so it is end-to-end encrypted either way. The plain body is NEVER labelled ratcheted.
 */
export async function chooseWireBody(
  a: { body: string; peerFingerprint: string; canDeposit: boolean; ownerRatchet?: RatchetIdentity; peerRatchet?: RatchetPeer },
  io: RatchetIO = realRatchetIO,
): Promise<{ wireBody: string; ratcheted: boolean }> {
  if (!a.canDeposit || !a.ownerRatchet || !a.peerRatchet) return { wireBody: a.body, ratcheted: false };
  // R5: the capability check, the advance and the persist are ONE read-modify-write; two tabs must not both advance from the same state.
  const unlock = await lockSession(io, a.peerFingerprint);
  try {
    if (!(await ratchetCapabilityObserved(a.peerFingerprint, io))) return { wireBody: a.body, ratcheted: false };
    const sealed = await sealDirectNote(a.peerFingerprint, a.body, a.ownerRatchet, a.peerRatchet, io);
    if (!sealed) throw new Error('direct ratchet could not seal');
    return { wireBody: sealed, ratcheted: true };
  } finally {
    unlock();
  }
}
