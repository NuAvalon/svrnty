// src/lib/relay/poll-subkey.ts
// N12 (#703): the in-memory poll key. An idle mailbox poll is signed by an ephemeral Ed25519 key that the long-term
// identity key delegated to ONCE (mintPollDelegation in mailbox-auth.ts), so a poll with no mail in it does not unlock
// the identity key. Spec: Flint S1-S7 (task:703 #1151, #1306), contract svrnty_N12_poll_subkey_v2.md.
//
// RULES THIS MODULE KEEPS (each has a test):
//   P1  the poll key and cert are NEVER persisted: module variables only, no storage API is touched anywhere in this file.
//   L   lock / identity switch DROPS them (the one session-lock hook, same as unlock-cycle.ts), and a mint that was in
//       flight when that happened is discarded, so nothing created after a lock survives it. The next poll mints a NEW
//       key (a different poll_pub). The relay is stateless and cannot revoke on lock; exposure of a stolen key + cert
//       is bounded by the cert's expires_ts (1 h by default, relay cap 24 h).
//   P3  the identity key is touched only at mint: one unlock per cert, none per idle poll.
import type { UnlockCycle } from '@/lib/crypto/unlock-cycle';
import { onSessionLock } from '@/lib/identity/client-store';
import { mintPollDelegation, signMailboxPollV2, type PollCert } from './mailbox-auth';

/** Mint a fresh cert when less than this is left, so a cert cannot lapse between signing here and the relay's check. */
export const POLL_REMINT_MARGIN_MS = 5 * 60 * 1000;

export class PollKeyDropped extends Error {
  constructor() {
    super('poll key dropped (session locked or identity switched while it was being minted)');
    this.name = 'PollKeyDropped';
  }
}

export interface PollOwner {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  kemPublicKey?: string;
  sigPublicKey?: string;
}

interface Held {
  fingerprint: string;
  mailboxId: string;
  secretKey: Uint8Array;
  cert: PollCert;
}

let held: Held | null = null;
let minting: Promise<Held> | null = null;
let epoch = 0; // bumped by every lock / identity switch

function wipe(h: Held | null): void {
  if (h) h.secretKey.fill(0); // best effort: JS cannot promise memory is gone, but nothing keeps a usable key
}

// Registered once at module load: the hook list is append-only (same reasoning as unlock-cycle.ts).
onSessionLock(() => {
  epoch += 1;
  wipe(held);
  held = null;
  minting = null;
});

/** Drop the poll key and cert now (also what a lock does). Idempotent. */
export function dropPollKey(): void {
  epoch += 1;
  wipe(held);
  held = null;
  minting = null;
}

/** Public facts only (never the secret) so tests and diagnostics can see which key is current. */
export function pollKeyState(): { held: boolean; pollPub?: string; expiresTs?: number } {
  return held ? { held: true, pollPub: held.cert.delegation.poll_pub, expiresTs: held.cert.delegation.expires_ts } : { held: false };
}

function usable(h: Held | null, owner: PollOwner, mailboxId: string, now: number, margin: number): h is Held {
  return (
    h !== null &&
    h.fingerprint === owner.fingerprint &&
    h.mailboxId === mailboxId &&
    now >= h.cert.delegation.issued_ts && // a clock that went backwards must not reuse a cert from its future
    h.cert.delegation.expires_ts - now > margin
  );
}

/**
 * The v2 poll header for `mailboxId`. Mints (and so unlocks the identity key, via `cycle`) only when no usable key is held;
 * otherwise signing is synchronous and touches no identity key at all. Concurrent callers share one mint.
 */
export async function pollHeaders(args: {
  owner: PollOwner;
  mailboxId: string;
  now: number;
  cycle?: UnlockCycle;
  lifetimeMs?: number;
  remintMarginMs?: number;
}): Promise<Record<string, string>> {
  const margin = args.remintMarginMs ?? POLL_REMINT_MARGIN_MS;
  if (!usable(held, args.owner, args.mailboxId, args.now, margin)) {
    if (!minting) {
      const e = epoch;
      const p = (async (): Promise<Held> => {
        const m = await mintPollDelegation({
          mailboxId: args.mailboxId,
          fingerprint: args.owner.fingerprint,
          publicKeyArmored: args.owner.publicKeyArmored,
          privateKeyArmored: args.owner.privateKeyArmored,
          passphrase: args.owner.passphrase,
          cycle: args.cycle,
          now: args.now,
          lifetimeMs: args.lifetimeMs,
          kemPublicKey: args.owner.kemPublicKey,
          sigPublicKey: args.owner.sigPublicKey,
        });
        const h: Held = { fingerprint: args.owner.fingerprint, mailboxId: args.mailboxId, secretKey: m.secretKey, cert: m.cert };
        if (e !== epoch) {
          wipe(h); // locked or switched mid-mint: nothing created after the lock survives it
          throw new PollKeyDropped();
        }
        held = h;
        return h;
      })();
      minting = p;
      const clear = () => { if (minting === p) minting = null; };
      p.then(clear, clear); // a failed mint is never cached
    }
    const mp = minting as Promise<Held>; // set above or already in flight
    const h = await mp;
    // Joined someone else's mint for another identity/mailbox: refuse rather than sign under a cert that is not ours.
    if (h.fingerprint !== args.owner.fingerprint || h.mailboxId !== args.mailboxId) throw new PollKeyDropped();
    return signMailboxPollV2({ cert: h.cert, secretKey: h.secretKey, mailboxId: args.mailboxId, now: args.now });
  }
  return signMailboxPollV2({ cert: held.cert, secretKey: held.secretKey, mailboxId: args.mailboxId, now: args.now });
}
