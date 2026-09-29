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
import type { RingChannel } from './types';

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
  return {
    channel_id: newId('ring'),
    local_label: localLabel.trim() || 'Ring',
    member_fingerprints: unique,
    key_epoch: 1,
    content_key_b64: toBase64(randomBytes(32)),
    created_at: now,
    rotated_at: now,
  };
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
  };
}

/** What the relay is allowed to know: nothing about membership — only deposit targets. */
export function ringDepositTargets(channel: RingChannel): string[] {
  return [...channel.member_fingerprints];
}
