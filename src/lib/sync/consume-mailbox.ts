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

import type { UnlockCycle } from '@/lib/crypto/unlock-cycle';
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
import type { NoteWireV0 } from '@/lib/messaging/types';
import { asMailboxEnvelopePackage } from './hybrid-dual-read';
import type { ReceiptWireV0 } from '@/lib/crypto/delivery-receipt';

/** The mailbox owner's identity — needed to sign poll/ack requests (owner-auth). */
export interface OwnerIdentity {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  /** One unlock per poll cycle, shared by the decryptors and the poll/ack signers; the caller drops it at cycle end. */
  cycle?: UnlockCycle;
  // §5 canonical-id: the identity's PQ public keys, threaded into the owner-auth bundle so the relay
  // can recompute the 64-hex canonical fingerprint. Absent for a classical identity (40-hex fp).
  kemPublicKey?: string;
  sigPublicKey?: string;
  // HNDL receive (custody ①, Peter #168173): the owner's ML-KEM-1024 SECRET (base64). The FE path
  // (buildConsumeDeps) instead sources this from loadPQKeys(fp) because the browser vault holds it;
  // a HEADLESS agent has no IndexedDB, so its custody→HeadlessOwner adapter MUST carry the secret
  // HERE (from MintSecret.mlkem1024Sec, uint8ToBase64) so buildHeadlessConsumeDeps can derive the
  // hybrid open-material (deriveOwnerHybridSecrets) and open inbound PQ-hybrid mail. Absent for a
  // classical identity → classical-only openers (per the loud-not-silent invariant: advertising a
  // kem PUB while this is absent must error LOUD, never silently ack+drop a hybrid blob).
  kemSecretKey?: string;
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

/**
 * OVER-WIRE NOTE routing seam (svrnty-note-v0) — the mailbox's THIRD inbound type. A note is sealed
 * to the owner with the SAME openpgp envelope as contact.updates + joiner-responses (seal.ts →
 * contact-update-envelope.ts pattern), so — exactly like a joiner-response — it DECRYPTS NON-NULL via
 * the contact-update decryptor below and would then be dropped on its missing `envelope.fingerprint`
 * → silently ack-DELETED. The always-on living-book poll would therefore EAT every over-wire note
 * before any inbox consumer saw it (the silent-loss). This seam routes notes FIRST, by their own
 * type-checked decryptor, so over-wire RECEIVE actually delivers.
 *   • verify — decrypt + type-check the blob as a note (noteOpenpgpDecryptor returns null for a
 *     non-note, incl. a contact.update/joiner → fall through to the contact-update path). Returns the
 *     NoteWireV0, or null. Does NOT authenticate — that's accept's job (the note can be forged until
 *     verifyNoteSender runs), mirroring sign-before-admit.
 *   • accept — authenticate (verifyNoteSender: public_key↔from_fingerprint + signature) THEN admit
 *     (in-book) THEN persist to the notes store (= acceptInboundNote). Returns the persisted note's
 *     ids for the inbox repaint, or null if DROPPED (unsigned / forged / stranger — silent I-1/I-2,
 *     the SAME custody as a stranger contact-update: terminal + acked, never echoed). THROWS only on
 *     a store I/O failure → retryable (putNote is idempotent on note_id, so redelivery re-persists
 *     harmlessly). Kept crypto/IndexedDB-free here — the caller (live-book-poll) wires it.
 * Optional: a caller that omits it keeps the exact prior behaviour (notes, if any, fall to the
 * contact-update path — i.e. the silent-loss; so the runtime binding MUST wire this once over-wire ships).
 */
export interface NoteResponseSeam {
  verify: (blob: string) => Promise<NoteWireV0 | null>;
  accept: (wire: NoteWireV0) => Promise<AcceptedNote | null>;
}

/** The persisted note's handles, returned by the note seam's accept for the inbox live-repaint. */
export interface AcceptedNote {
  note_id: string;
  thread_id: string;
  from_fingerprint: string;
}

/** Emitted after a note is persisted so the inbox repaints live (separate from the contact-book beat). */
export interface NoteLiveEvent {
  note_id: string;
  thread_id: string;
  from_fingerprint: string;
}

/**
 * DELIVERY-RECEIPT routing seam (svrnty-receipt-v0) — the mailbox's FOURTH inbound type. A receipt is
 * sealed to the owner with the SAME openpgp envelope as the other four (seal.ts sealReceiptTo), so —
 * exactly like them — it DECRYPTS NON-NULL via the contact-update decryptor and would then be dropped on
 * its missing `envelope.fingerprint` → silently ack-DELETED (the silent-loss). This seam routes a receipt
 * FIRST, by its own type-checked decryptor, so the sender's "Delivered" graduation actually lands. It is
 * the WIRE that makes "Sent · unconfirmed." a TRANSIENT state for a delivered note (it resolves when the
 * recipient's receipt arrives) — the sender half of delivery-receipt.ts.
 *   • verify — decrypt + type-check the blob as a receipt (receiptOpenpgpDecryptor returns null for a
 *     non-receipt → fall through). Does NOT authenticate — that's accept's job (the receipt's claimed
 *     nonce/note are meaningless until verifyReceiptWire runs against the stored outbound note).
 *   • accept — recover the OUTBOUND note (getNote), look up the recipient's pubkeys, and
 *     verifyReceiptWire. ★ delivered=true is written ON EXACTLY ONE LINE (inside accept, only on
 *     verify-true) — NEVER from a bare ack, a relay flag, or any unverified signal. Returns the note's
 *     ids for the inbox repaint, or null if DROPPED (no matching note / forged / unverifiable recipient —
 *     silent I-1, floor 'Sent · unconfirmed.' holds, NO false Delivered). THROWS only on store I/O →
 *     retryable (putNote is idempotent, so a redelivered receipt re-sets delivered harmlessly).
 * Optional: a caller that omits it keeps the exact prior behaviour (a receipt, if any, falls to the
 * contact-update path = the silent-loss; so the runtime binding MUST wire this once over-wire ships).
 */
export interface ReceiptResponseSeam {
  verify: (blob: string) => Promise<ReceiptWireV0 | null>;
  accept: (wire: ReceiptWireV0) => Promise<AcceptedReceipt | null>;
}

/** The confirmed note's handles, returned by the receipt seam's accept for the inbox delivered-repaint. */
export interface AcceptedReceipt {
  note_id: string;
  thread_id: string;
  from_fingerprint: string; // the delivering recipient's fingerprint (for the repaint)
}

/** Emitted after a receipt is verified + the note marked delivered, so the inbox repaints the status. */
export interface ReceiptLiveEvent {
  note_id: string;
  thread_id: string;
  from_fingerprint: string;
}

export interface ConsumeDeps {
  owner: OwnerIdentity;
  decrypt: EnvelopeDecryptor;
  store: ContactStore;
  joiner?: JoinerResponseSeam; // R1 return-channel (KNOWN tier); omit to disable joiner routing
  note?: NoteResponseSeam; // over-wire note routing; omit → notes fall to contact-update path (silent-loss)
  receipt?: ReceiptResponseSeam; // delivery-receipt routing; omit → receipts fall to contact-update path (silent-loss)
  relayBase?: string; // default '/api/relay'
  fetchImpl?: typeof fetch; // default global fetch (inject for tests)
  emit?: (event: LiveApplyEvent) => void; // live-beat seam (contact book)
  emitNote?: (event: NoteLiveEvent) => void; // inbox-repaint seam (over-wire notes)
  emitReceipt?: (event: ReceiptLiveEvent) => void; // inbox delivered-repaint seam (delivery receipts)
  now?: () => string; // ISO timestamp source (inject for determinism)
  // ③ HNDL receive gate (Flint): true iff the owner ADVERTISES a kem pub but NO ML-KEM secret could be
  // derived (OwnerIdentity.kemPublicKey present && deriveOwnerHybridSecrets → undefined). Set by the deps
  // builders (buildConsumeDeps / buildHeadlessConsumeDeps). When true, consumeOne treats a hybrid-package
  // blob it cannot open as RETRYABLE (loud), never terminal — so inbound hybrid is never silently lost
  // while the secret is transiently missing (locked session / Athena-① pending). Undefined ⇒ status quo.
  // May be a lazy check (FE: the secret is only derived once a hybrid blob arrives); consumeOne awaits it per hybrid blob.
  hybridSecretMissing?: boolean | (() => Promise<boolean>);
  // #720: called once per CLEAN poll with the number of blobs kept because this device cannot open them yet (0 clears the notice).
  // Counts only that case; a terminal drop is not "held". Never called for a refused poll or an ended unlock cycle.
  // `expiresAt` (ISO) is the EARLIEST relay deadline among the held envelopes, present only when EVERY held envelope carried a valid one:
  // one "kept until" date has to be true for every message the count includes, and a missing or malformed date proves nothing.
  emitHeld?: (count: number, info?: { expiresAt?: string }) => void;
}

export interface ConsumeSummary {
  polled: number;
  applied: number;
  ignited: number;
  notes: number; // over-wire notes persisted to the inbox (distinct from contact-book applies)
  delivered: number; // delivery receipts verified → outbound notes marked delivered (the "Delivered" graduation)
  dropped: number; // rejected/undecryptable/not-in-book — silently
  held: number; // #720: hybrid packages KEPT on the relay because no kem secret is derivable yet (also counted in `dropped`, as before)
  acked: number;
  rejected?: number; // HTTP status when the poll request itself was refused (e.g. 401 owner-auth); absent on a clean poll — a rejected poll is NOT an empty mailbox
}

type Outcome =
  | { kind: 'applied'; event: LiveApplyEvent }
  | { kind: 'note'; event: NoteLiveEvent } // over-wire note persisted → ack + inbox repaint (NOT a book beat)
  | { kind: 'receipt'; event: ReceiptLiveEvent } // delivery receipt verified → note marked delivered → ack + inbox repaint
  | { kind: 'terminal' } // permanently invalid (bad sig, stale, not-for-me, not-in-book) → ack to clean up
  | { kind: 'retryable' } // e.g. epoch-ahead-needs-lineage → leave for a later poll after lineage catch-up
  | { kind: 'held' }; // #720: a hybrid package this owner cannot open YET (no derivable kem secret): retryable AND counted, so the UI can say so

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
  const summary: ConsumeSummary = { polled: 0, applied: 0, ignited: 0, notes: 0, delivered: 0, dropped: 0, held: 0, acked: 0 };

  // 1) Poll as owner (signed request — the bare GET occupancy oracle is closed server-side).
  const pollHeaders = await signMailboxPollRequest({
    mailboxId,
    fingerprint: deps.owner.fingerprint,
    publicKeyArmored: deps.owner.publicKeyArmored,
    privateKeyArmored: deps.owner.privateKeyArmored,
    passphrase: deps.owner.passphrase,
    cycle: deps.owner.cycle,
    kemPublicKey: deps.owner.kemPublicKey,
    sigPublicKey: deps.owner.sigPublicKey,
    now: Date.now(),
  });
  const res = await doFetch(`${relayBase}/queue?mailbox_id=${encodeURIComponent(mailboxId)}`, { headers: pollHeaders });
  if (!res.ok) {
    summary.rejected = res.status;
    return summary;
  }
  // expires_at is the relay's own deletion time for the envelope (additive on the poll; absent from an older relay). Untrusted: only
  // ever compared and handed on, never used to decide whether a blob is consumed.
  const envelopes = (await res.json()) as Array<{ envelope_id: string; blob: string; expires_at?: unknown }>;
  if (!Array.isArray(envelopes)) return summary;
  summary.polled = envelopes.length;

  // 2) Consume each envelope independently; collect the terminal ones to ack.
  const toAck: string[] = [];
  const heldExpiries: unknown[] = [];
  for (const env of envelopes) {
    // N10: the poll-cycle unlock ended (identity locked/switched mid-tick). Everything left is UNDECIDED, not
    // undecryptable: stop and leave it in the mailbox; never decrypt/persist the rest under another identity.
    if (deps.owner.cycle?.ended) break;
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
    // A cycle that died DURING this blob makes it look undecryptable (decryptors throw → terminal → ack-delete).
    // That is a lock/switch artefact, not a verdict on the blob: downgrade so it is never ack-deleted.
    if (outcome.kind === 'terminal' && deps.owner.cycle?.ended) outcome = { kind: 'retryable' };
    if (outcome.kind === 'applied') {
      summary.applied++;
      if (outcome.event.ignited) summary.ignited++;
      toAck.push(env.envelope_id);
      try {
        deps.emit?.(outcome.event);
      } catch {
        /* the live-beat is best-effort; a repaint failure must not block consume/ack */
      }
    } else if (outcome.kind === 'note') {
      summary.notes++;
      toAck.push(env.envelope_id); // persisted to the inbox → consumed, ack-delete
      try {
        deps.emitNote?.(outcome.event);
      } catch {
        /* inbox repaint is best-effort; a repaint failure must not block consume/ack */
      }
    } else if (outcome.kind === 'receipt') {
      summary.delivered++;
      toAck.push(env.envelope_id); // note marked delivered → consumed, ack-delete
      try {
        deps.emitReceipt?.(outcome.event);
      } catch {
        /* inbox delivered-repaint is best-effort; a repaint failure must not block consume/ack */
      }
    } else if (outcome.kind === 'terminal') {
      summary.dropped++;
      toAck.push(env.envelope_id); // clean up permanently-invalid mail (silently)
    } else if (outcome.kind === 'held') {
      summary.held++;
      heldExpiries.push(env.expires_at);
      summary.dropped++; // unchanged accounting: a held blob has always counted as not-consumed this poll
    } else {
      summary.dropped++; // retryable — leave in the mailbox for a later poll
    }
  }

  // #720: report how many blobs are being KEPT because this device cannot open them yet. Reported on every CLEAN poll, including 0, so a
  // notice clears once they open or expire. NOT reported when the poll was refused (returned above) or the unlock cycle ended mid-tick:
  // in both the state of the mailbox is unknown, and an unknown state must neither raise nor clear the notice.
  if (!deps.owner.cycle?.ended) {
    try {
      deps.emitHeld?.(summary.held, { expiresAt: earliestExpiry(heldExpiries) });
    } catch {
      /* the notice is best-effort; a repaint failure must not block consume/ack */
    }
  }

  // 3) Ack-delete the terminal envelopes (owner-signed). apply is idempotent, so a crash before ack
  //    just redelivers and re-applies harmlessly (at-least-once).
  // Cycle ended mid-tick → skip the ack entirely (it can't be signed anyway): already-applied envelopes redeliver
  //    and re-apply idempotently; the rest were never decided.
  if (toAck.length > 0 && !deps.owner.cycle?.ended) {
    const ackHeaders = await signMailboxAckRequest({
      mailboxId,
      envelopeIds: toAck,
      fingerprint: deps.owner.fingerprint,
      publicKeyArmored: deps.owner.publicKeyArmored,
      privateKeyArmored: deps.owner.privateKeyArmored,
      passphrase: deps.owner.passphrase,
      cycle: deps.owner.cycle,
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

/** The earliest valid expiry among `raw`, as ISO; undefined if there are none, or if ANY entry is missing or not a valid date. */
function earliestExpiry(raw: readonly unknown[]): string | undefined {
  if (raw.length === 0) return undefined;
  let min = Number.POSITIVE_INFINITY;
  for (const r of raw) {
    const t = typeof r === 'string' ? Date.parse(r) : Number.NaN;
    if (!Number.isFinite(t)) return undefined;
    if (t < min) min = t;
  }
  return new Date(min).toISOString();
}

async function consumeOne(blob: string, deps: ConsumeDeps, now: () => string): Promise<Outcome> {
  // N10 (Flint #178422 blocking 1): a lock can land AFTER key() handed the key out and BEFORE we persist. Re-check the
  // cycle immediately before EVERY write below, not just at blob boundaries: a dead cycle means the identity is
  // locked/switched, so the decided-looking result must not be applied — leave the envelope in the mailbox (retryable).
  const dead = () => deps.owner.cycle?.ended === true;
  // ③ LOUD-not-silent (Flint, HNDL receive gate): a hybrid deposit we SHOULD be able to open — the owner
  // ADVERTISES a kem pub but we currently have NO derived ML-KEM secret (Athena-① pending / a transiently
  // locked session) — must NEVER be acked+DELETED (= silent-loss). Leave it for RETRY, loudly. KEYED ON
  // secret-DERIVABILITY, not open-success: when we HAVE the secret, a hybrid pkg that fails to open is
  // genuinely terminal (corrupt / wrong-recipient) and is handled by the normal decrypt path below.
  if (
    deps.hybridSecretMissing &&
    asMailboxEnvelopePackage(blob) != null &&
    (typeof deps.hybridSecretMissing === 'function' ? await deps.hybridSecretMissing() : true)
  ) {
    console.error(
      `[consume] LOUD: hybrid deposit for kem-advertising owner ${deps.owner.fingerprint.slice(0, 8)} ` +
      `with no derivable ML-KEM secret — leaving for RETRY, not acking (acking would be silent-loss). ` +
      `Needs the owner's kem secret (OwnerIdentity.kemSecretKey / vault PQ bundle) or a session unlock.`,
    );
    return { kind: 'held' };
  }

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
      if (dead()) return { kind: 'retryable' };
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

  // OVER-WIRE NOTE ROUTING (svrnty-note-v0) — same discipline as the joiner seam above, and for the
  // same reason: a note decrypts NON-NULL via the contact-update decryptor below, then drops on its
  // missing `envelope.fingerprint` → it would be silently ack-DELETED. Route it FIRST by its own
  // type-checked decryptor. note.verify returns null for a non-note (contact.update / joiner), which
  // falls through unharmed — so this can never eat a contact-update (note-type ≠ contact-update shape).
  if (deps.note) {
    let wire: NoteWireV0 | null;
    try {
      wire = await deps.note.verify(blob);
    } catch {
      wire = null; // a throwing note-verify is treated as not-a-note → fall through (fail-safe)
    }
    if (wire) {
      try {
        if (dead()) return { kind: 'retryable' };
        const accepted = await deps.note.accept(wire);
        // persisted (signed + admitted) → note (ack + inbox repaint); dropped (unsigned / forged /
        // stranger) → terminal (silent ack — I-1/I-2, the same custody as a stranger contact-update).
        return accepted
          ? { kind: 'note', event: { note_id: accepted.note_id, thread_id: accepted.thread_id, from_fingerprint: accepted.from_fingerprint } }
          : { kind: 'terminal' };
      } catch (err) {
        // A store I/O failure while persisting a VERIFIED note → leave for retry (at-least-once).
        // acceptInboundNote's putNote is idempotent on note_id, so a redelivered note re-persists harmlessly.
        console.error('[return-channel] note accept failed (left for retry):', err);
        return { kind: 'retryable' };
      }
    }
    // wire null → not a note → fall through to the contact-update consume path.
  }

  // DELIVERY-RECEIPT ROUTING (svrnty-receipt-v0) — same discipline as the joiner + note seams
  // above, same reason: a receipt decrypts NON-NULL via the contact-update decryptor, then drops on its
  // missing `envelope.fingerprint` → silently ack-DELETED. Route it by its own type-checked decryptor.
  // receipt.verify returns null for a non-receipt (note / joiner / contact-update → fall through
  // unharmed), so this can never eat another type (4-way no-cross-swallow — receipt-type ≠ the others).
  // accept recovers the outbound note + verifies the recipient's signature → marks it delivered.
  if (deps.receipt) {
    let wire: ReceiptWireV0 | null;
    try {
      wire = await deps.receipt.verify(blob);
    } catch {
      wire = null; // a throwing receipt-verify is treated as not-a-receipt → fall through (fail-safe)
    }
    if (wire) {
      try {
        if (dead()) return { kind: 'retryable' };
        const confirmed = await deps.receipt.accept(wire);
        // verified (matches a stored outbound note + recipient sig checks) → receipt (ack + delivered-repaint);
        // dropped (no matching note / forged / unverifiable recipient) → terminal (silent ack — I-1, the
        // floor 'Sent · unconfirmed.' holds, NO false Delivered).
        return confirmed
          ? { kind: 'receipt', event: { note_id: confirmed.note_id, thread_id: confirmed.thread_id, from_fingerprint: confirmed.from_fingerprint } }
          : { kind: 'terminal' };
      } catch (err) {
        // A store I/O failure while marking a VERIFIED note delivered → leave for retry (at-least-once).
        // putNote is idempotent on note_id, so a redelivered receipt re-sets delivered harmlessly.
        console.error('[return-channel] receipt accept failed (left for retry):', err);
        return { kind: 'retryable' };
      }
    }
    // wire null → not a receipt → fall through to the contact-update consume path.
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
  if (dead()) return { kind: 'retryable' };
  await deps.store.persist(contact.current.id, applied.next);
  return { kind: 'applied', event: { id: contact.current.id, fingerprint: signed.envelope.fingerprint, ignited: applied.ignited } };
}
