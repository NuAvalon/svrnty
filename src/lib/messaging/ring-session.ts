// src/lib/messaging/ring-session.ts
// Small-group notes: a ring is a fan-out of the hybrid triple ratchet, plus threads.
//
// Each other member has their own TripleRatchet session. A ring note is the plaintext
// of that pairwise send, so confidentiality, forward secrecy, and post-compromise
// security are the triple ratchet's — not a shared content key every member retains.
// The relay sees one sealed mailbox blob per member and no roster, no group name.
//
// Membership change bumps the epoch and DROPS pair sessions. The next send is a fresh
// initiate to whoever remains. A removed member is not in that fan-out. Their old
// session cannot open the new initiate.
//
// CLAIM BOUNDARY: this is still notes, not the public word "messaging". The first
// flight of each epoch has the triple ratchet's initial-flight limit (recipient
// long-term keys re-open that flight). No one-time prekeys. Cap is MAX_RING_MEMBERS.
// Two members initiating at once is two sessions; the first packet to arrive for a
// peer that we do not yet have a session for is acceptFirst, and a failed receive
// does not get replaced by a second init (that would let a forged blob clobber a
// live session).
import { TripleRatchet, type RatchetIdentity, type RatchetPacket, type RatchetPeer } from '@/lib/crypto/message-ratchet';
import type { ParticipantKind, RingSessionSnapshot } from './types';

/** Including yourself. Small on purpose — naive fan-out, not MLS. */
export const MAX_RING_MEMBERS = 8;

export interface RingPeer extends RatchetPeer {
  fingerprint: string;
}

export interface RingNotePlain {
  v: 1;
  channel_id: string;
  epoch: number;
  members: string[];
  note_id: string;
  thread_id: string;
  sender_fp: string;
  sent_at: string;
  body: string;
  participant_kind: ParticipantKind;
  reply_to?: string;
  thread_root?: string;
}

export interface RingOutbound {
  fingerprint: string;
  packet: RatchetPacket;
}

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

function isId(value: unknown): value is string {
  return typeof value === 'string' && ID_RE.test(value);
}

function sameMembers(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sb = new Set(b);
  return a.every((m) => sb.has(m));
}

function parsePlain(text: string): RingNotePlain | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  if (o.v !== 1) return null;
  if (!isId(o.channel_id) || !isId(o.note_id) || !isId(o.thread_id) || !isId(o.sender_fp)) return null;
  if (typeof o.epoch !== 'number' || !Number.isSafeInteger(o.epoch) || o.epoch < 1) return null;
  if (typeof o.sent_at !== 'string' || o.sent_at.length > 40) return null;
  if (typeof o.body !== 'string' || o.body.length > 16_000) return null;
  if (o.participant_kind !== 'human' && o.participant_kind !== 'agent') return null;
  if (!Array.isArray(o.members) || o.members.length < 2 || o.members.length > MAX_RING_MEMBERS) return null;
  if (!o.members.every((m) => typeof m === 'string' && isId(m))) return null;
  const members = [...new Set(o.members as string[])];
  if (members.length !== o.members.length) return null;
  const replyTo = o.reply_to;
  const threadRoot = o.thread_root;
  const hasReply = replyTo !== undefined;
  const hasRoot = threadRoot !== undefined;
  if (hasReply !== hasRoot) return null;
  if (hasReply && (!isId(replyTo) || !isId(threadRoot))) return null;
  const plain: RingNotePlain = {
    v: 1,
    channel_id: o.channel_id,
    epoch: o.epoch,
    members,
    note_id: o.note_id,
    thread_id: o.thread_id,
    sender_fp: o.sender_fp,
    sent_at: o.sent_at,
    body: o.body,
    participant_kind: o.participant_kind,
  };
  if (hasReply && isId(replyTo) && isId(threadRoot)) {
    plain.reply_to = replyTo;
    plain.thread_root = threadRoot;
  }
  return plain;
}

function encodePlain(plain: RingNotePlain): string {
  const body: Record<string, unknown> = {
    v: 1,
    channel_id: plain.channel_id,
    epoch: plain.epoch,
    members: plain.members,
    note_id: plain.note_id,
    thread_id: plain.thread_id,
    sender_fp: plain.sender_fp,
    sent_at: plain.sent_at,
    body: plain.body,
    participant_kind: plain.participant_kind,
  };
  if (plain.reply_to && plain.thread_root) {
    body.reply_to = plain.reply_to;
    body.thread_root = plain.thread_root;
  }
  return JSON.stringify(body);
}

/**
 * One ring epoch on this device. Holds a triple ratchet per other member.
 * Identity secrets are arguments to send/receive, never fields.
 */
export class RingSession {
  readonly channelId: string;
  readonly selfFp: string;
  epoch: number;
  members: string[];
  private sessions = new Map<string, TripleRatchet>();

  private constructor(channelId: string, selfFp: string, members: string[], epoch: number) {
    this.channelId = channelId;
    this.selfFp = selfFp;
    this.members = members;
    this.epoch = epoch;
  }

  static create(channelId: string, selfFp: string, members: string[], epoch = 1): RingSession {
    if (!isId(channelId) || !isId(selfFp)) throw new Error('ring: bad channel or self id');
    if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error('ring: bad epoch');
    const unique = [...new Set(members.filter((m) => isId(m)))];
    if (unique.length !== members.length) throw new Error('ring: member ids must be unique and well-formed');
    if (unique.length < 2 || unique.length > MAX_RING_MEMBERS) {
      throw new Error(`ring: need 2–${MAX_RING_MEMBERS} members`);
    }
    if (!unique.includes(selfFp)) throw new Error('ring: self must be a member');
    return new RingSession(channelId, selfFp, unique, epoch);
  }

  static importSnapshot(snap: RingSessionSnapshot | null | undefined): RingSession | null {
    if (!snap || snap.v !== 1) return null;
    let session: RingSession;
    try {
      session = RingSession.create(snap.channel_id, snap.self_fp, snap.members, snap.epoch);
    } catch {
      return null;
    }
    if (!Array.isArray(snap.pairs)) return null;
    for (const pair of snap.pairs) {
      if (!pair || !isId(pair.fingerprint) || !session.members.includes(pair.fingerprint)) return null;
      if (pair.fingerprint === session.selfFp) return null;
      const ratchet = TripleRatchet.importState(pair.snapshot);
      if (!ratchet) return null;
      session.sessions.set(pair.fingerprint, ratchet);
    }
    return session;
  }

  exportSnapshot(): RingSessionSnapshot {
    return {
      v: 1,
      channel_id: this.channelId,
      epoch: this.epoch,
      self_fp: this.selfFp,
      members: [...this.members],
      pairs: [...this.sessions.entries()].map(([fingerprint, ratchet]) => ({
        fingerprint,
        snapshot: ratchet.exportState(),
      })),
    };
  }

  /**
   * Membership change. Epoch increments, pair sessions are dropped.
   * `nextMembers` includes self. The removed fingerprint is simply absent.
   */
  rekey(nextMembers: string[]): void {
    const unique = [...new Set(nextMembers)];
    if (!unique.includes(this.selfFp)) throw new Error('ring: rekey dropped self');
    if (unique.length < 2 || unique.length > MAX_RING_MEMBERS) {
      throw new Error(`ring: need 2–${MAX_RING_MEMBERS} members`);
    }
    if (!unique.every((m) => isId(m))) throw new Error('ring: bad member id');
    this.members = unique;
    this.epoch += 1;
    this.sessions.clear();
  }

  others(): string[] {
    return this.members.filter((fp) => fp !== this.selfFp);
  }

  /**
   * Seal one note to every other current member. Partial peer lists throw —
   * a ring send that skips someone by accident would desync the epoch.
   * The body is stamped with this epoch, the member list, and our fingerprint.
   */
  async send(
    self: RatchetIdentity,
    peers: RingPeer[],
    note: Omit<RingNotePlain, 'v' | 'channel_id' | 'epoch' | 'members' | 'sender_fp'>,
  ): Promise<RingOutbound[]> {
    const wanted = this.others();
    if (peers.length !== wanted.length) throw new Error('ring: send needs every other member');
    const byFp = new Map(peers.map((p) => [p.fingerprint, p]));
    for (const fp of wanted) {
      if (!byFp.has(fp)) throw new Error('ring: missing member key');
    }
    if (note.reply_to || note.thread_root) {
      if (!isId(note.reply_to) || !isId(note.thread_root)) throw new Error('ring: bad reply thread');
    }
    const plain: RingNotePlain = {
      v: 1,
      channel_id: this.channelId,
      epoch: this.epoch,
      members: [...this.members],
      note_id: note.note_id,
      thread_id: note.thread_id,
      sender_fp: this.selfFp,
      sent_at: note.sent_at,
      body: note.body,
      participant_kind: note.participant_kind,
    };
    if (note.reply_to && note.thread_root) {
      plain.reply_to = note.reply_to;
      plain.thread_root = note.thread_root;
    }
    const text = encodePlain(plain);
    const out: RingOutbound[] = [];
    for (const fp of wanted) {
      const peer = byFp.get(fp)!;
      let ratchet = this.sessions.get(fp);
      if (!ratchet) ratchet = TripleRatchet.initiate(self, peer);
      const packet = await ratchet.send(text);
      this.sessions.set(fp, ratchet);
      out.push({ fingerprint: fp, packet });
    }
    return out;
  }

  /**
   * Open one member's packet. Null on tamper, a non-member, a stale epoch,
   * or a body that names a different sender. A failed open does not replace
   * a live session. A higher epoch from a current member adopts the new
   * roster carried in the note and drops the other pair sessions.
   */
  async receive(
    self: RatchetIdentity,
    from: RingPeer,
    packet: RatchetPacket,
  ): Promise<RingNotePlain | null> {
    if (!this.members.includes(from.fingerprint) || from.fingerprint === this.selfFp) return null;
    const existing = this.sessions.get(from.fingerprint);

    const adopt = (trial: TripleRatchet, text: string, freshEpoch: boolean): RingNotePlain | null => {
      const plain = parsePlain(text);
      if (!plain) return null;
      if (plain.channel_id !== this.channelId) return null;
      if (plain.sender_fp !== from.fingerprint) return null;
      if (!plain.members.includes(this.selfFp) || !plain.members.includes(from.fingerprint)) return null;
      if (plain.epoch < this.epoch) return null;
      if (freshEpoch && plain.epoch <= this.epoch) return null;
      if (plain.epoch === this.epoch && !sameMembers(plain.members, this.members)) return null;
      if (plain.epoch > this.epoch) {
        this.members = [...plain.members];
        this.epoch = plain.epoch;
        this.sessions.clear();
      }
      this.sessions.set(from.fingerprint, trial);
      return plain;
    };

    if (existing) {
      const trial = existing.clone();
      const text = await trial.receive(packet);
      if (text !== null) return adopt(trial, text, false);
      // A failed receive must not clobber the live session. A higher-epoch
      // initiate (membership rekey) is the one fresh handshake we accept.
      const accepted = await TripleRatchet.acceptFirst(self, from, packet);
      if (!accepted) return null;
      return adopt(accepted.session, accepted.plaintext, true);
    }

    const accepted = await TripleRatchet.acceptFirst(self, from, packet);
    if (!accepted) return null;
    return adopt(accepted.session, accepted.plaintext, false);
  }
}
