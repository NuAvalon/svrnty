// src/lib/sync/send-contact-update.ts
// The SEND composer for 0.4 contact.update — the sender counterpart of consume-mailbox.ts. When the
// card owner edits a method, this signs the change ONCE and produces one encrypted, addressed deposit
// per recipient for the return-channel mailbox. It is PURE (no fetch): it returns the deposit tuples;
// the caller (ContactMethodReviseDialog's sendFn) POSTs each to /api/relay/envelope. Kept fetch-free so
// it is unit-testable and the UI injects the owner identity + the recipient lookup.
//
// SECURITY SHAPE (why this is safe):
//  • SIGN ONCE — the signature is over the envelope, so it is identical for every recipient; each
//    recipient's verifyIncomingContactUpdate checks it against the sender's card they already hold
//    (authenticity + I-7 tamper-evidence). buildAndSign enforces the field firewall + honest manifest,
//    so an unsendable change fails LOUD here before anything is encrypted.
//  • ENCRYPT PER-RECIPIENT — encryptContactUpdateTo(signed, recipient pubkey) → opaque armored blob;
//    the relay stores ciphertext only (custody / I-1: it cannot read contacts or reconstruct the edge).
//  • ADDRESS by deriveMailboxId(recipient fingerprint) — the same deterministic mailbox id the
//    recipient polls with (documented-leak bounded by I-4).
//  • FAIL-CLOSED PER RECIPIENT — a recipient with no usable public key is SKIPPED and reported, NEVER
//    sent to in a downgraded/cleartext form; and one recipient's key error never aborts the batch.

import { deriveMailboxId } from '../relay/mailbox-auth';
import { encryptContactUpdateTo } from './contact-update-envelope';
import { buildAndSignContactUpdate, type BuildContactUpdateArgs } from '../trust/contact-update-sign';

/** The card owner's signing identity (from the unlocked vault). pq secret present ⇒ hybrid suite. */
export interface ContactUpdateOwner {
  fingerprint: string;
  epoch: number;
  privateKeyArmored: string;
  passphrase: string;
  pqSigningSecretKey?: Uint8Array;
}

/** A recipient who holds the owner's card: fingerprint (→ mailbox) + armored pubkey (→ encrypt-to). */
export interface ContactUpdateRecipient {
  fingerprint: string;
  publicKeyArmored: string;
}

/** One ready-to-POST deposit for /api/relay/envelope. */
export interface ContactUpdateDeposit {
  mailbox_id: string;
  blob: string;
}

/** The batch result — honest per-recipient accounting so the UI can say "sent to N of M" truthfully. */
export interface ContactUpdateSendPlan {
  deposits: ContactUpdateDeposit[];
  skipped: Array<{ fingerprint: string; reason: 'bad-fingerprint' | 'no-public-key' | 'encrypt-failed' }>;
}

/** The change the owner is publishing: the delta + the NEW monotonic card version. */
export interface ContactUpdateChange {
  version: number;
  delta: Record<string, unknown>;
  updated_at?: string; // inject for determinism; else now()
}

/**
 * Sign the change ONCE and produce one encrypted, addressed deposit per recipient. Pure — the caller
 * POSTs each {mailbox_id, blob} to /api/relay/envelope. A recipient without a usable public key is
 * SKIPPED (reported), never sent to in a downgraded form (fail-closed per recipient); a single
 * recipient's encrypt error is reported and does not abort the rest of the batch.
 *
 * Throws (does NOT partially send) only if the change itself is unsendable — buildAndSign rejects it
 * (field outside the allowlist, empty delta, junk version): a whole-update failure, before any deposit.
 */
export async function buildContactUpdateDeposits(
  change: ContactUpdateChange,
  owner: ContactUpdateOwner,
  recipients: ContactUpdateRecipient[],
): Promise<ContactUpdateSendPlan> {
  const args: BuildContactUpdateArgs = {
    fingerprint: owner.fingerprint,
    epoch: owner.epoch,
    version: change.version,
    delta: change.delta,
    updated_at: change.updated_at,
  };

  // Sign once. buildAndSign enforces the firewall + honest manifest → an unsendable change throws
  // here (whole-update failure) before we encrypt or address anything.
  const signed = await buildAndSignContactUpdate(
    args,
    owner.privateKeyArmored,
    owner.passphrase,
    owner.pqSigningSecretKey,
  );

  const deposits: ContactUpdateDeposit[] = [];
  const skipped: ContactUpdateSendPlan['skipped'] = [];

  for (const r of recipients) {
    if (typeof r.fingerprint !== 'string' || r.fingerprint.length === 0) {
      skipped.push({ fingerprint: String(r?.fingerprint), reason: 'bad-fingerprint' });
      continue;
    }
    if (typeof r.publicKeyArmored !== 'string' || r.publicKeyArmored.length === 0) {
      // No key ⇒ we cannot E2E-encrypt to them. SKIP — never send cleartext/downgraded.
      skipped.push({ fingerprint: r.fingerprint, reason: 'no-public-key' });
      continue;
    }
    try {
      const blob = await encryptContactUpdateTo(signed, r.publicKeyArmored);
      deposits.push({ mailbox_id: deriveMailboxId(r.fingerprint), blob });
    } catch {
      // A malformed/unreadable recipient key must not abort the batch.
      skipped.push({ fingerprint: r.fingerprint, reason: 'encrypt-failed' });
    }
  }

  return { deposits, skipped };
}

/** Outcome of actually POSTing the deposits — honest per-recipient accounting for a "sent to N of M" UI. */
export interface SendContactUpdateResult {
  /** mailbox_ids that accepted the deposit (relay 200). */
  deposited: string[];
  /** recipients skipped before POST (no/bad key) — carried from buildContactUpdateDeposits. */
  skipped: ContactUpdateSendPlan['skipped'];
  /** deposits whose POST failed (relay non-2xx or network error) — retryable, not a crypto failure. */
  failed: Array<{ mailbox_id: string; status: number | string }>;
}

/**
 * The drop-in: sign once, encrypt per-recipient, and POST each deposit to the return-channel mailbox.
 * The "mailbox deposit" the stub reserves for Flint. Pure of UI concern — the caller (dialog) supplies
 * change/owner/recipients and maps this result to its own UX. Each POST is independent: one failure is
 * collected, never aborts the batch (at-least-once; the recipient's version floor makes re-send idempotent).
 * Throws only if the change itself is unsendable (buildContactUpdateDeposits' firewall) — before any POST.
 */
export async function sendContactUpdate(
  change: ContactUpdateChange,
  owner: ContactUpdateOwner,
  recipients: ContactUpdateRecipient[],
  opts: { fetchImpl?: typeof fetch; relayBase?: string } = {},
): Promise<SendContactUpdateResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const relayBase = opts.relayBase ?? '/api/relay';

  const { deposits, skipped } = await buildContactUpdateDeposits(change, owner, recipients);

  const deposited: string[] = [];
  const failed: SendContactUpdateResult['failed'] = [];
  for (const d of deposits) {
    try {
      const res = await doFetch(`${relayBase}/envelope`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mailbox_id: d.mailbox_id, blob: d.blob }),
      });
      if (res.ok) deposited.push(d.mailbox_id);
      else failed.push({ mailbox_id: d.mailbox_id, status: res.status });
    } catch {
      failed.push({ mailbox_id: d.mailbox_id, status: 'network-error' });
    }
  }

  return { deposited, skipped, failed };
}
