// src/lib/sync/consume-mailbox.ts
// The RETURN-CHANNEL CONSUME→APPLY CALLER — the client half of the living address book (demo Step-4).
// Alice polls her mailbox as owner, and for each pending envelope runs the one legitimate consume
// path: decrypt → verify → apply → persist → ack. A delivered contact.update, once verified, flows
// into the SAME living-wins apply as import/cluster dedup (applyVerifiedContactUpdate refreshes the
// local decay clock → a DIM contact re-ignites to LIVING = the bloom). This is §9.1's merge on the
// consume side (joint design §3). Nothing here is smart about the social graph — the relay never was.
//
// SEAMS (deliberately injected, not hardcoded):
//   • decrypt — the E2E crypto is its own lane. The relay stores an OPAQUE blob; only the recipient
//     decrypts it to a SignedContactUpdate. Injected so the pipeline is crypto-agnostic + testable,
//     and so the classical↔hybrid-PQ choice swaps with ZERO caller change (see contact-update-envelope.ts).
//   • store — lookup(fingerprint) + persist(id, updates). Injected so the pipeline is IndexedDB-free
//     and unit-testable; the demo passes a client-store adapter.
//   • emit — the live-beat seam (contact-events.ts). Called after a
//     successful apply so the open book repaints live (source:'broadcast' honesty). Injected so this
//     module never hard-depends on the (unmerged) emitter.
//
// CUSTODY (whitelist-on-fetch, I-2): an update whose sender fingerprint is NOT in Alice's book is
// DROPPED unread. REJECTIONS ARE SILENT (I-1/I-2): reject reasons are local diagnostics, NEVER echoed
// to the sender or relay — so the return channel can't be turned into a "are you my contact?" oracle.

import { deriveMailboxId, signMailboxPollRequest, signMailboxAckRequest } from '@/lib/relay/mailbox-auth';
import {
  verifyIncomingContactUpdate,
  ContactUpdateRejected,
  type SignedContactUpdate,
  type KnownContactIdentity,
} from '@/lib/trust/contact-update';
import {
  applyVerifiedContactUpdate,
  ContactUpdateApplyRejected,
  type StoredContact,
} from '@/lib/contacts/apply-contact-update';
import type { PendingJoiner } from '@/lib/trust/joiner-response';

/** The mailbox owner's identity — needed to sign poll/ack requests (owner-auth). */
export interface OwnerIdentity {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  // §5 canonical-id: the identity's PQ public keys, threaded into the owner-auth bundle so the relay
  // can recompute the 64-hex canonical fingerprint. Absent for a classical identity (40-hex fp).
  kemPublicKey?: string;
  sigPublicKey?: string;
}

/** Decrypt an opaque relay blob to a SignedContactUpdate, or null if it isn't for us / is corrupt. */
export type EnvelopeDecryptor = (blob: string) => Promise<SignedContactUpdate | null>;

/** What the store returns for a known contact: the verify seam + the record to apply onto. */
export interface KnownContact {
  known: KnownContactIdentity;
  current: StoredContact;
}

/** The store operations the caller needs — injected so the pipeline stays IndexedDB-free + testable. */
export interface ContactStore {
  /** The receiver's last-verified identity + current record for `fingerprint`, or null if not in the book. */
  lookup(fingerprint: string): Promise<KnownContact | null>;
  /** Persist an applied update. */
  persist(id: string, next: StoredContact): Promise<void>;
}

/** Emitted after a successful apply so the live book repaints (reason:'live-apply' seam). */
export interface LiveApplyEvent {
  id: string;
  fingerprint: string;
  ignited: boolean;
}

/**
 * R1 RETURN-CHANNEL (KNOWN tier) — the pending-joiner routing seam (pinned by
 * joiner-response.e2e.test.ts). The mailbox is shared by TWO inbound message types encrypted to the
 * owner with the SAME openpgp envelope: contact.updates AND joiner-responses. They CANNOT be told apart
 * by "which decrypt returned non-null" — the contact-update decryptor DECRYPTS a joiner-response fine
 * (returns non-null) and would then drop it on its missing `envelope.fingerprint`, LOSING the joiner.
 * The only correct discriminator is WHICH VERIFY SUCCEEDS. This optional seam supplies the joiner-side
 * verify+accept so consumeOne can try it FIRST:
 *   • verify — try the RAW blob as a joiner-response (it decrypts internally + checks giver-binding,
 *     the solicited-gate oracle, Invariant-1, and the signature). Returns the KNOWN PendingJoiner, or
 *     null for anything that is not a solicited, well-signed joiner-response (→ fall through to the
 *     contact-update path). Injected pre-bound to the owner identity + a per-poll accept-oracle snapshot.
 *   • accept — surface a VERIFIED joiner as KNOWN (idempotent add) and record the (code, verified-fp)
 *     accept. Returns {ignited} for a fresh add, or null if the joiner is already in the book (a no-op
 *     that still acks/records). Kept crypto/IndexedDB-free here — the caller (live-book-poll) wires it.
 * Optional: a caller with no return channel (unit tests, legacy) omits it and behaves exactly as before.
 */
export interface JoinerResponseSeam {
  verify: (blob: string) => Promise<PendingJoiner | null>;
  accept: (pj: PendingJoiner) => Promise<{ ignited: boolean } | null>;
}

export interface ConsumeDeps {
  owner: OwnerIdentity;
  decrypt: EnvelopeDecryptor;
  store: ContactStore;
  joiner?: JoinerResponseSeam; // R1 return-channel (KNOWN tier); omit to disable joiner routing
  relayBase?: string; // default '/api/relay'
  fetchImpl?: typeof fetch; // default global fetch (inject for tests)
  emit?: (event: LiveApplyEvent) => void; // live-beat seam
  now?: () => string; // ISO timestamp source (inject for determinism)
}

export interface ConsumeSummary {
  polled: number;
  applied: number;
  ignited: number;
  dropped: number; // rejected/undecryptable/not-in-book — silently
  acked: number;
}

type Outcome =
  | { kind: 'applied'; event: LiveApplyEvent }
  | { kind: 'terminal' } // permanently invalid (bad sig, stale, not-for-me, not-in-book) → ack to clean up
  | { kind: 'retryable' }; // e.g. epoch-ahead-needs-lineage → leave for a later poll after lineage catch-up

/**
 * Poll the owner's mailbox once, consume every pending envelope through verify→apply→persist, ack the
 * ones that reached a terminal state (applied or permanently-invalid — silently), and leave retryable
 * ones for a later poll. Returns a summary. Never throws on a single bad envelope — one poisoned
 * message cannot wedge the channel.
 */
export async function consumeInboundContactUpdates(deps: ConsumeDeps): Promise<ConsumeSummary> {
  const relayBase = deps.relayBase ?? '/api/relay';
  const doFetch = deps.fetchImpl ?? fetch;
  const now = deps.now ?? (() => new Date().toISOString());
  const mailboxId = deriveMailboxId(deps.owner.fingerprint);
  const summary: ConsumeSummary = { polled: 0, applied: 0, ignited: 0, dropped: 0, acked: 0 };

  // 1) Poll as owner (signed request — the bare GET occupancy oracle is closed server-side).
  const pollHeaders = await signMailboxPollRequest({
    mailboxId,
    fingerprint: deps.owner.fingerprint,
    publicKeyArmored: deps.owner.publicKeyArmored,
    privateKeyArmored: deps.owner.privateKeyArmored,
    passphrase: deps.owner.passphrase,
    kemPublicKey: deps.owner.kemPublicKey,
    sigPublicKey: deps.owner.sigPublicKey,
    now: Date.now(),
  });
  const res = await doFetch(`${relayBase}/queue?mailbox_id=${encodeURIComponent(mailboxId)}`, { headers: pollHeaders });
  if (!res.ok) return summary;
  const envelopes = (await res.json()) as Array<{ envelope_id: string; blob: string }>;
  if (!Array.isArray(envelopes)) return summary;
  summary.polled = envelopes.length;

  // 2) Consume each envelope independently; collect the terminal ones to ack.
  const toAck: string[] = [];
  for (const env of envelopes) {
    let outcome: Outcome;
    try {
      outcome = await consumeOne(env.blob, deps, now);
    } catch (err) {
      // WEDGE-IMMUNITY (the line-above invariant): consumeOne is not expected to throw, but if an
      // unexpected error escapes it (a store I/O failure, an unforeseen bug), ONE envelope must never
      // wedge the whole channel. Log LOUDLY (local only — never echoed, I-1) and treat as RETRYABLE:
      // leave it in the mailbox so a transient failure retries rather than silently dropping a
      // verified update, and a persistent one is bounded by the envelope TTL.
      console.error('[return-channel] unexpected error consuming an envelope (left for retry):', err);
      outcome = { kind: 'retryable' };
    }
    if (outcome.kind === 'applied') {
      summary.applied++;
      if (outcome.event.ignited) summary.ignited++;
      toAck.push(env.envelope_id);
      try {
        deps.emit?.(outcome.event);
      } catch {
        /* the live-beat is best-effort; a repaint failure must not block consume/ack */
      }
    } else if (outcome.kind === 'terminal') {
      summary.dropped++;
      toAck.push(env.envelope_id); // clean up permanently-invalid mail (silently)
    } else {
      summary.dropped++; // retryable — leave in the mailbox for a later poll
    }
  }

  // 3) Ack-delete the terminal envelopes (owner-signed). apply is idempotent, so a crash before ack
  //    just redelivers and re-applies harmlessly (at-least-once).
  if (toAck.length > 0) {
    const ackHeaders = await signMailboxAckRequest({
      mailboxId,
      envelopeIds: toAck,
      fingerprint: deps.owner.fingerprint,
      publicKeyArmored: deps.owner.publicKeyArmored,
      privateKeyArmored: deps.owner.privateKeyArmored,
      passphrase: deps.owner.passphrase,
      kemPublicKey: deps.owner.kemPublicKey,
      sigPublicKey: deps.owner.sigPublicKey,
      now: Date.now(),
    });
    const ackRes = await doFetch(`${relayBase}/ack`, {
      method: 'POST',
      headers: { ...ackHeaders, 'content-type': 'application/json' },
      body: JSON.stringify({ mailbox_id: mailboxId, envelope_ids: toAck }),
    });
    if (ackRes.ok) summary.acked = toAck.length;
  }

  return summary;
}

async function consumeOne(blob: string, deps: ConsumeDeps, now: () => string): Promise<Outcome> {
  // R1 RETURN-CHANNEL ROUTING (pinned by joiner-response.e2e.test.ts SEAM): try the
  // joiner-response VERIFY FIRST. It is the correct discriminator — a contact-update blob returns null
  // here (its decrypted shape lacks joiner_fingerprint → isWellFormed fails) and falls through unharmed;
  // a joiner-response verifies to a PendingJoiner. Routing by decrypt-null would silently LOSE every
  // joiner-response: it decrypts NON-null via the contact-update decryptor below, then drops on the
  // missing `envelope.fingerprint`. The two verifies are mutually exclusive (proven E2E), so
  // trying joiner-verify first can never eat a contact-update.
  if (deps.joiner) {
    let pj: PendingJoiner | null;
    try {
      pj = await deps.joiner.verify(blob);
    } catch {
      pj = null; // a throwing joiner-verify is treated as not-a-joiner → fall through (fail-safe)
    }
    if (pj) {
      try {
        const res = await deps.joiner.accept(pj);
        // accepted a fresh joiner → surface as an apply so the open book repaints (ignited); already in
        // the book → terminal (still ack + record, no repaint). Either way the envelope is consumed.
        return res
          ? { kind: 'applied', event: { id: pj.fingerprint, fingerprint: pj.fingerprint, ignited: res.ignited } }
          : { kind: 'terminal' };
      } catch (err) {
        // A store failure while accepting a VERIFIED joiner → leave for retry (at-least-once). The accept
        // is idempotent (fingerprint-dedup), so a redelivered blob re-adds harmlessly on a later poll.
        console.error('[return-channel] joiner accept failed (left for retry):', err);
        return { kind: 'retryable' };
      }
    }
    // pj null → not a solicited joiner-response → fall through to the contact-update consume path.
  }

  // decrypt — an undecryptable blob is not-for-us / corrupt: terminal (drop + ack), silently.
  let signed: SignedContactUpdate | null;
  try {
    signed = await deps.decrypt(blob);
  } catch {
    return { kind: 'terminal' };
  }
  if (!signed || typeof signed.envelope?.fingerprint !== 'string') return { kind: 'terminal' };

  // whitelist-on-fetch (I-2): an update from a fingerprint not in the book is dropped unread.
  const contact = await deps.store.lookup(signed.envelope.fingerprint);
  if (!contact) return { kind: 'terminal' };

  // verify — the one gate. epoch-ahead needs lineage catch-up first → retryable; all else terminal.
  let verified;
  try {
    verified = await verifyIncomingContactUpdate(signed, contact.known);
  } catch (e) {
    const retryable = e instanceof ContactUpdateRejected && e.reason === 'epoch-ahead-needs-lineage';
    return { kind: retryable ? 'retryable' : 'terminal' };
  }

  // apply — pure living-wins over the current record. stale-version = already applied → terminal.
  let applied;
  try {
    applied = applyVerifiedContactUpdate(contact.current, verified, now());
  } catch (e) {
    if (e instanceof ContactUpdateApplyRejected) return { kind: 'terminal' };
    throw e; // an unexpected (non-ApplyRejected) error → propagates to the guarded consume loop (wedge-immune)
  }

  // persist may throw on a store I/O failure — that too propagates to the guarded loop (retryable).
  await deps.store.persist(contact.current.id, applied.next);
  return { kind: 'applied', event: { id: contact.current.id, fingerprint: signed.envelope.fingerprint, ignited: applied.ignited } };
}
