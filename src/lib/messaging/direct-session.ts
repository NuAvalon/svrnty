// 1:1 notes → TripleRatchet. Calls the fleet ratchet; does not reimplement KDF / DH / KEM.
//
// OpenPGP still wraps the mailbox blob (existing deposit). The inner body is a ratchet
// packet when both sides have X25519 + ML-KEM. Legacy plaintext bodies stay accepted.
// isPQEncapLive() stays false until Flint flips it. Do not market this as Signal-grade.

import { TripleRatchet, type RatchetIdentity, type RatchetPacket, type RatchetPeer } from '@/lib/crypto/message-ratchet';
import { getRatchetSession, putRatchetSession } from './store';

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

/** Seal plaintext for one peer. Persists the session. Null if the ratchet cannot start. */
export async function sealDirectNote(
  peerFingerprint: string,
  plaintext: string,
  self: RatchetIdentity,
  peer: RatchetPeer,
): Promise<string | null> {
  const snap = await getRatchetSession(peerFingerprint);
  let session = snap ? TripleRatchet.importState(snap) : null;
  if (!session) {
    if (snap) return null; // corrupt snapshot — fail closed, do not mint a parallel session
    session = TripleRatchet.initiate(self, peer);
  }
  const packet = await session.send(plaintext);
  await putRatchetSession(peerFingerprint, session.exportState());
  return encodeBody(packet);
}

/** Open a ratchet body from one peer. Persists the session. Null on tamper / missing keys. */
export async function openDirectNote(
  peerFingerprint: string,
  body: string,
  self: RatchetIdentity,
  peer: RatchetPeer,
): Promise<string | null> {
  const packet = decodeBody(body);
  if (!packet) return null;
  const snap = await getRatchetSession(peerFingerprint);
  if (snap) {
    const session = TripleRatchet.importState(snap);
    if (!session) return null;
    const pt = await session.receive(packet);
    if (pt === null) return null;
    await putRatchetSession(peerFingerprint, session.exportState());
    return pt;
  }
  const first = await TripleRatchet.acceptFirst(self, peer, packet);
  if (!first) return null;
  await putRatchetSession(peerFingerprint, first.session.exportState());
  return first.plaintext;
}
