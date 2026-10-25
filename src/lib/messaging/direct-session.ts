// 1:1 notes → TripleRatchet. Calls the fleet ratchet; does not reimplement KDF / DH / KEM.
//
// OpenPGP still wraps the mailbox blob (existing deposit). The inner body is a ratchet
// packet when both sides have X25519 + ML-KEM. Legacy plaintext bodies stay accepted.
// isPQEncapLive() stays false until Flint flips it. Do not market this as Signal-grade.

import { TripleRatchet, type RatchetIdentity, type RatchetPacket, type RatchetPeer, type RatchetSnapshot } from '@/lib/crypto/message-ratchet';
import { readRatchetSession, putRatchetSession, type RatchetSessionRead } from './store';

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
  put: (peerFingerprint: string, snapshot: RatchetSnapshot) => Promise<void>;
}
export const realRatchetIO: RatchetIO = { read: readRatchetSession, put: putRatchetSession };

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

/** Seal plaintext for one peer. Persists the session. Null if the ratchet cannot start. */
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
  await io.put(peerFingerprint, session.exportState());
  return encodeBody(packet);
}

/** Open a ratchet body from one peer. Persists the session. Null on tamper / missing keys. */
export async function openDirectNote(
  peerFingerprint: string,
  body: string,
  self: RatchetIdentity,
  peer: RatchetPeer,
  io: RatchetIO = realRatchetIO,
): Promise<string | null> {
  const packet = decodeBody(body);
  if (!packet) return null;
  const cur = await io.read(peerFingerprint);
  if (cur.state === 'unreadable') return null; // R3: never acceptFirst over an unreadable row (it would overwrite the real session)
  if (cur.state === 'ok') {
    const session = TripleRatchet.importState(cur.snapshot);
    if (!session) return null;
    const pt = await session.receive(packet);
    if (pt === null) return null;
    await io.put(peerFingerprint, session.exportState());
    return pt;
  }
  const first = await TripleRatchet.acceptFirst(self, peer, packet);
  if (!first) return null;
  await io.put(peerFingerprint, first.session.exportState());
  return first.plaintext;
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
  if (!(await ratchetCapabilityObserved(a.peerFingerprint, io))) return { wireBody: a.body, ratcheted: false };
  const sealed = await sealDirectNote(a.peerFingerprint, a.body, a.ownerRatchet, a.peerRatchet, io);
  if (!sealed) throw new Error('direct ratchet could not seal');
  return { wireBody: sealed, ratcheted: true };
}
