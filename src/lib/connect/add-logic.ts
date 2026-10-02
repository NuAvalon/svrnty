// src/lib/connect/add-logic.ts
//
// Typed stub for one-step Connect-UX. Apollo wires resolve / land / promote
// post-flip. This module MUST NOT call relay decrypt, identity persist, or
// grow-gate admit — those are fleet-owned. Flip isConnectAddLogicLive() WITH
// the real implementation.

import { isConnectAddLogicLive } from '../claim-gates';
import type { ParsedConnectLink } from './parse-connect-link';

export type ConnectEntityType = 'agent' | 'human' | 'org';

export type ConnectCard = {
  displayName: string;
  handle?: string;
  /** Canonical fingerprint hex when the resolve hook supplies it. */
  fingerprint: string;
  /** Armored identity pubkey — display inert; never as HTML. */
  publicKeyArmored?: string;
  mailboxPointer?: string;
  /**
   * Self-attested entity type from the signed card. ABSENT = not yet attested.
   * NEVER default to 'human'. Label as "attested", never "verified".
   */
  entityType?: ConnectEntityType;
};

export type ResolveResult =
  | { ok: true; card: ConnectCard }
  | { ok: false; reason: 'not_wired' | 'invalid' | 'unavailable' };

export type LandResult =
  | { ok: true; state: 'gate' }
  | { ok: false; reason: 'not_wired' | 'no_identity' | 'failed' };

/** Promote is Known only. Trust is a later, separate act — never a default here. */
export type PromoteChoice = 'known';

export type PromoteResult =
  | { ok: true; state: 'known' }
  | { ok: false; reason: 'not_wired' | 'not_in_gate' | 'failed' };

export { isConnectAddLogicLive };

/**
 * Resolve a parsed connect link to the newcomer's shareable card.
 * Stub: always not_wired while the claim gate is false.
 */
export async function resolveConnectLink(
  link: ParsedConnectLink,
): Promise<ResolveResult> {
  if (!link?.code) return { ok: false, reason: 'invalid' };
  if (!isConnectAddLogicLive()) return { ok: false, reason: 'not_wired' };
  return { ok: false, reason: 'not_wired' };
}

/**
 * Land the resolved card in GATE (pending), never Known.
 * Stub: refuses while the claim gate is false.
 */
export async function landInGate(card: ConnectCard): Promise<LandResult> {
  if (!card?.fingerprint) return { ok: false, reason: 'failed' };
  if (!isConnectAddLogicLive()) return { ok: false, reason: 'not_wired' };
  return { ok: false, reason: 'not_wired' };
}

/**
 * Explicit one-tap Gate → Known. `choice` must be 'known' — Trusted is not offered.
 */
export async function promoteGateToKnown(
  fingerprint: string,
  choice: PromoteChoice,
): Promise<PromoteResult> {
  if (choice !== 'known') return { ok: false, reason: 'failed' };
  if (!fingerprint) return { ok: false, reason: 'failed' };
  if (!isConnectAddLogicLive()) return { ok: false, reason: 'not_wired' };
  return { ok: false, reason: 'not_wired' };
}
