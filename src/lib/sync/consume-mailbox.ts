// src/lib/sync/consume-mailbox.ts
// The RETURN-CHANNEL CONSUME→APPLY CALLER — the client half of the living address book (demo Step-4).
// Alice polls her mailbox as owner, and for each pending envelope runs the one legitimate consume
// path: decrypt → verify → apply → persist → ack. A delivered contact.update, once verified, flows
// into the SAME living-wins apply as import/cluster dedup (applyVerifiedContactUpdate refreshes the
// local decay clock → a DIM contact re-ignites to LIVING = the bloom). This is §9.1's merge on the
// consume side (joint design §3). Nothing here is smart about the social graph — the relay never was.
//
// SEAMS (deliberately injected, not hardcoded):
//   • decrypt — the E2E crypto is Flint's lane. The relay stores an OPAQUE blob; only the recipient
//     decrypts it to a SignedContactUpdate. Injected so the pipeline is crypto-agnostic + testable,
//     and so the classical↔hybrid-PQ choice swaps with ZERO caller change (see contact-update-envelope.ts).
//   • store — lookup(fingerprint) + persist(id, updates). Injected so the pipeline is IndexedDB-free
//     and unit-testable; the demo passes a client-store adapter.
//   • emit — Apollo's live-beat seam (PR#32 contact-events.ts, not yet on main). Called after a
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

/** The mailbox owner's identity — needed to sign poll/ack requests (owner-auth). */
export interface OwnerIdentity {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
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

/** Emitted after a successful apply so the live book repaints (Apollo's reason:'live-apply' seam). */
export interface LiveApplyEvent {
  id: string;
  fingerprint: string;
  ignited: boolean;
}

export interface ConsumeDeps {
  owner: OwnerIdentity;
  decrypt: EnvelopeDecryptor;
  store: ContactStore;
  relayBase?: string; // default '/api/relay'
  fetchImpl?: typeof fetch; // default global fetch (inject for tests)
  emit?: (event: LiveApplyEvent) => void; // Apollo live-beat seam
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
    const outcome = await consumeOne(env.blob, deps, now);
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
    throw e; // an unexpected error is a real bug — surface it, don't swallow
  }

  await deps.store.persist(contact.current.id, applied.next);
  return { kind: 'applied', event: { id: contact.current.id, fingerprint: signed.envelope.fingerprint, ignited: applied.ignited } };
}
