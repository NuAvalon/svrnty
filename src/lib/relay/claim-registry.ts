// src/lib/relay/claim-registry.ts
// Layer (A) beta-access CLAIM REGISTRY — tracks which DUMB mailboxes have redeemed a beta-access token
// (= "has messaging"). Format §6 / Archie bearer-not-registry (criterion 2):
//
//   STORE ONLY { mailbox_id -> { claimed: bool, redeemedJti: Set<jti> } }.
//   NEVER a durable { token <-> fp <-> mailbox } correlation table.
//
// The mailbox_id is already known to the relay (the owner hands it over on every poll, mailbox-auth.ts
// DOCUMENTED LEAK — transient, not persisted). The fp / sub / token payload NEVER touch this registry.
// So the claim adds NO new persistent linkage vs. what a poll already reveals transiently — it records
// only the coarse per-mailbox fact "claimed" + the redeemed jti-ids (one-time + revocation handle).
//
// In-memory, per-process (single-node), same posture as mailbox-store.ts (Redis later). Lazy-create.

interface ClaimState {
  claimed: boolean;
  redeemedJti: Set<string>;
}

declare global {
  // eslint-disable-next-line no-var
  var __claimRegistry: Map<string, ClaimState> | undefined;
}

function getRegistry(): Map<string, ClaimState> {
  if (!globalThis.__claimRegistry) globalThis.__claimRegistry = new Map();
  return globalThis.__claimRegistry;
}

/** Has this mailbox redeemed a beta-access token (= the owner may receive/read)? */
export function isMailboxClaimed(mailboxId: string): boolean {
  return getRegistry().get(mailboxId)?.claimed === true;
}

/** Has this jti already been redeemed for this mailbox (one-time; §3.4)? */
export function isJtiRedeemed(mailboxId: string, jti: string): boolean {
  return getRegistry().get(mailboxId)?.redeemedJti.has(jti) === true;
}

/**
 * Mark the mailbox claimed + record the redeemed jti. Idempotent (§3.5): re-presenting the same jti for
 * an already-claimed mailbox is a no-op that still reads as claimed. Stores NOTHING that links the
 * mailbox to an identity or a token body — status + jti-ids only.
 */
export function recordClaim(mailboxId: string, jti: string): void {
  const reg = getRegistry();
  const state = reg.get(mailboxId) ?? { claimed: false, redeemedJti: new Set<string>() };
  state.claimed = true;
  state.redeemedJti.add(jti);
  reg.set(mailboxId, state);
}
