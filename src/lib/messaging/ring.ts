// src/lib/messaging/ring.ts
// Ring-channels (Phase 3.4 sketch) — groups that don't out you to the relay.
//
// • Shared symmetric content key, distributed via per-member envelopes (seal wrap).
// • Rotation on membership change (key_epoch++).
// • Relay sees ciphertext to K mailboxes — NO roster table, NO group name server-side.
// • MLS later if N outgrows naïve fan-out.
//
// This module is LOCAL STATE + key lifecycle helpers. It does not talk to the network.

import { randomBytes } from '@noble/hashes/utils.js';
import { MAX_RING_MEMBERS, RING_HISTORY_LIMIT } from './ring-session';
import type { RingChannel, RingHistoryAccess } from './types';

export { RING_HISTORY_LIMIT };

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function newId(prefix: string): string {
  return `${prefix}_${toBase64(randomBytes(12)).replace(/[+/=]/g, '').slice(0, 16)}`;
}

/** Create a ring channel with a fresh AES-256 content key (local only). */
export function createRingChannel(
  localLabel: string,
  memberFingerprints: string[],
  now: string = new Date().toISOString(),
): RingChannel {
  const unique = [...new Set(memberFingerprints.filter(Boolean))];
  if (unique.length < 2) {
    throw new Error('ring-channel needs at least 2 members');
  }
  if (unique.length > MAX_RING_MEMBERS) {
    throw new Error(`ring-channel holds at most ${MAX_RING_MEMBERS} members`);
  }
  const member_history: NonNullable<RingChannel['member_history']> = {};
  for (const fp of unique) member_history[fp] = { history: 'previous', since_epoch: 1 };
  return {
    channel_id: newId('ring'),
    local_label: localLabel.trim() || 'Ring',
    member_fingerprints: unique,
    key_epoch: 1,
    content_key_b64: toBase64(randomBytes(32)),
    created_at: now,
    rotated_at: now,
    member_history,
  };
}

/**
 * Add someone. Epoch bumps, pair sessions drop, so old blobs are not readable
 * with the new epoch. `history` defaults to `new`: earlier notes are not resealed.
 * `previous` records that the adder should reseal the notes this device still holds.
 */
export function addRingMember(
  channel: RingChannel,
  fingerprint: string,
  history: RingHistoryAccess = 'new',
  now: string = new Date().toISOString(),
): RingChannel {
  const fp = fingerprint.trim();
  if (!fp) throw new Error('ring-channel add needs a fingerprint');
  if (channel.member_fingerprints.includes(fp)) {
    throw new Error('ring-channel member is already in the ring');
  }
  if (channel.member_fingerprints.length + 1 > MAX_RING_MEMBERS) {
    throw new Error(`ring-channel holds at most ${MAX_RING_MEMBERS} members`);
  }
  const next = rotateRingMembership(channel, [...channel.member_fingerprints, fp], now);
  const member_history = { ...(channel.member_history ?? {}) };
  member_history[fp] = {
    history,
    since_epoch: history === 'previous' ? 1 : next.key_epoch,
  };
  return { ...next, member_history };
}

/** Remove someone from later notes. Notes they already opened stay with them. */
export function removeRingMember(
  channel: RingChannel,
  fingerprint: string,
  now: string = new Date().toISOString(),
): RingChannel {
  if (!channel.member_fingerprints.includes(fingerprint)) {
    throw new Error('ring-channel member is not in the ring');
  }
  const next = rotateRingMembership(
    channel,
    channel.member_fingerprints.filter((fp) => fp !== fingerprint),
    now,
  );
  const member_history = { ...(channel.member_history ?? {}) };
  delete member_history[fingerprint];
  return { ...next, member_history };
}

/**
 * Membership change → new content key + epoch bump.
 * Callers must re-wrap the new key to each remaining member (seal) and fan-out;
 * this function only mutates local channel state.
 */
export function rotateRingMembership(
  channel: RingChannel,
  nextMembers: string[],
  now: string = new Date().toISOString(),
): RingChannel {
  const unique = [...new Set(nextMembers.filter(Boolean))];
  if (unique.length < 2) {
    throw new Error('ring-channel needs at least 2 members after rotation');
  }
  return {
    ...channel,
    member_fingerprints: unique,
    key_epoch: channel.key_epoch + 1,
    content_key_b64: toBase64(randomBytes(32)),
    rotated_at: now,
    // Old pair sessions belong to the previous epoch. The next send initiates fresh.
    session_snapshot: undefined,
  };
}

/** What the relay is allowed to know: nothing about membership — only deposit targets. */
export function ringDepositTargets(channel: RingChannel): string[] {
  return [...channel.member_fingerprints];
}

export interface SharedNote {
  note_id: string;
  sent_at: string;
  from_fingerprint: string;
  body: string;
  reply_to?: string;
  thread_root?: string;
}

/**
 * Notes to reseal when someone joins. `new` (default) shares nothing.
 * `previous` shares the most recent notes this device still holds, oldest first.
 */
export function notesToShare<T extends SharedNote>(notes: T[], history: RingHistoryAccess): SharedNote[] {
  if (history !== 'previous') return [];
  const sorted = notes.slice().sort((a, b) => a.sent_at.localeCompare(b.sent_at) || a.note_id.localeCompare(b.note_id));
  return sorted.slice(-RING_HISTORY_LIMIT).map((n) => ({
    note_id: n.note_id,
    sent_at: n.sent_at,
    from_fingerprint: n.from_fingerprint,
    body: n.body,
    ...(n.reply_to && n.thread_root ? { reply_to: n.reply_to, thread_root: n.thread_root } : {}),
  }));
}
