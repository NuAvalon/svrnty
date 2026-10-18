// src/lib/crypto/beacon-matcher.ts
// #588 Mutual-Trust Beacon — the satellite's OBLIVIOUS MATCHER (v2 spec PIN2 + PIN3 / SIGNAL-1 event).
//
// Full spec: /app/shared/outbox/apollo/apollo_588_construction_v2.md
//
// The server is a STRICT oblivious matcher. It holds deposits per slot but NEVER exposes slot
// occupancy (PIN2 "no-peek"): the ONLY read is `poll(myTag)` → your own mailbox. On a match (two
// DISTINCT valid ring-members deposited at a slot) it ATOMICALLY delivers each party's counterpart
// DH-PSI share into BOTH mailboxes in one action (PIN3); a post-match withdrawal is INERT (you cannot
// un-ring the bell). That makes the match EVENT symmetric: a party cannot learn the counterpart
// deposited without the counterpart simultaneously learning theirs — closing OP-5 (counterpart
// de-anon by reading the shared slot) AND the probe-oracle (deposit→check→withdraw).
//
// What the server CANNOT do (by construction here): read who deposited (ring sig is anonymous over the
// whole enrolled directory), link a tag to an identity, or reveal a one-present slot to anyone. The
// mutual BOND itself (consistent-M) is verified CLIENT-side (beacon-psi) — the server only matches
// ring-membership + tag-distinctness and relays shares.

import { ringVerify, type RingSignature } from './beacon-lrs';
import { bytesToHex } from '@noble/curves/utils.js';

type Directory = Parameters<typeof ringVerify>[0];

type RPointHex = string;

/** Fixed deposit message — the LRS is signed over (slot, BEACON_MSG). */
export const BEACON_MSG = new TextEncoder().encode('svrnty-beacon-deposit-v2');

export interface BeaconDeposit {
  /** Linkable tag (= lrs.tag). Identifies "a ring member at this slot" without identity. */
  tag: string;
  /** The depositor's DH-PSI share D = x·H_G(s‖epoch), hex. Opaque to the server. */
  share: RPointHex;
  /** Ring signature over (slot, BEACON_MSG) proving enrolled-directory membership. */
  lrs: RingSignature;
}

export interface DepositResult {
  accepted: boolean;
  reason?: string;
  /** True iff THIS deposit completed a match (two distinct members present). */
  matched: boolean;
}

/**
 * In-memory model of the oblivious matcher (the real one is the satellite service; this models the
 * protocol invariants for test + reference). Ring = the enrolled directory (ristretto255 points).
 */
export class BeaconMatcher {
  private ring: Directory;
  private slots = new Map<string, BeaconDeposit[]>(); // slot → deposits (NEVER exposed; PIN2)
  private mailboxes = new Map<string, RPointHex[]>(); // tag → delivered counterpart shares (the only read)
  private matched = new Set<string>(); // slots that have matched (delivery done; withdrawal inert)
  private peerOf = new Map<string, string>(); // tag → its matched counterpart tag (set at match)
  private confirmBoxes = new Map<string, string[]>(); // tag → peer bond-confirmations (FINDING-1 round)

  constructor(directory: Directory) {
    this.ring = directory;
  }

  /**
   * Submit a deposit at a slot. Verifies ring-membership + binds the share to the ring tag.
   * On the second DISTINCT member, atomically delivers both shares (PIN3). No occupancy is ever revealed.
   */
  deposit(slot: Uint8Array, dep: BeaconDeposit): DepositResult {
    const slotKey = toKey(slot);
    // Gate 1: valid ring signature over (slot, BEACON_MSG) — enrolled member, no identity revealed.
    if (!ringVerify(this.ring, slot, BEACON_MSG, dep.lrs)) {
      return { accepted: false, matched: false, reason: 'invalid ring signature' };
    }
    // Gate 2: the deposit's tag must be the signature's tag (bind share↔member).
    if (dep.tag !== dep.lrs.tag) {
      return { accepted: false, matched: false, reason: 'tag/signature mismatch' };
    }
    const deps = this.slots.get(slotKey) ?? [];
    // Idempotent: same member re-depositing at the same slot (same tag) is a no-op, not a 2nd member.
    if (deps.some((d) => d.tag === dep.tag)) {
      return { accepted: true, matched: this.matched.has(slotKey), reason: 'idempotent re-deposit' };
    }
    deps.push(dep);
    this.slots.set(slotKey, deps);

    // Match: ≥2 DISTINCT tags ⇒ two distinct enrolled members at this (pair-secret) slot.
    const distinct = [...new Map(deps.map((d) => [d.tag, d])).values()];
    if (distinct.length >= 2 && !this.matched.has(slotKey)) {
      const [a, b] = distinct; // the pair
      // PIN3: ATOMIC dual-delivery — each party's share into the OTHER's mailbox, in one action.
      this.deliver(a.tag, b.share);
      this.deliver(b.tag, a.share);
      // Record the pairing so the mandatory bond-confirmation round can be relayed (FINDING-1).
      this.peerOf.set(a.tag, b.tag);
      this.peerOf.set(b.tag, a.tag);
      this.matched.add(slotKey);
      return { accepted: true, matched: true };
    }
    return { accepted: true, matched: false };
  }

  /** PIN2: the ONLY read. Poll YOUR tag's mailbox → the counterpart's share(s) iff matched. No slot peek. */
  poll(myTag: string): RPointHex[] {
    return [...(this.mailboxes.get(myTag) ?? [])];
  }

  /**
   * FINDING-1 bond-confirmation round: after a match, each party publishes H(M) via its tag; the
   * matcher relays it to the paired counterpart's confirm-box. Only works for a matched tag (no
   * confirm channel exists pre-match) — so the confirmation is strictly a post-match, paired exchange.
   */
  confirm(myTag: string, confirmHex: string): { relayed: boolean } {
    const peer = this.peerOf.get(myTag);
    if (!peer) return { relayed: false }; // not part of a matched pair
    const box = this.confirmBoxes.get(peer) ?? [];
    box.push(confirmHex);
    this.confirmBoxes.set(peer, box);
    return { relayed: true };
  }

  /** Poll the peer's bond-confirmation(s) delivered to MY tag. Client lights mutual only via mutualConfirmed(). */
  pollConfirm(myTag: string): string[] {
    return [...(this.confirmBoxes.get(myTag) ?? [])];
  }

  /** Withdraw an UNMATCHED deposit. Post-match the delivery already happened → INERT (returns false). */
  withdraw(slot: Uint8Array, myTag: string): { withdrawn: boolean } {
    const slotKey = toKey(slot);
    if (this.matched.has(slotKey)) return { withdrawn: false }; // PIN3: can't un-ring the bell
    const deps = (this.slots.get(slotKey) ?? []).filter((d) => d.tag !== myTag);
    this.slots.set(slotKey, deps);
    return { withdrawn: true };
  }

  private deliver(toTag: string, share: RPointHex): void {
    const box = this.mailboxes.get(toTag) ?? [];
    box.push(share);
    this.mailboxes.set(toTag, box);
  }
}

function toKey(slot: Uint8Array): string {
  return bytesToHex(slot);
}
