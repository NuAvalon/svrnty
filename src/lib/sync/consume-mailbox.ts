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
import type { OpenLegCounter } from './open-leg-counter';
import { classifyBlob, makeDeadLetterRow, planBound, recordKeyFor, type BenignTerminal, type DeadLetterReason, type DeadLetterRow } from './dead-letter';

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
  /** null = dropped for an unspecified reason (legacy; recorded as verify-failed). A DroppedNote says WHY, so the record is honest. */
  accept: (wire: NoteWireV0) => Promise<AcceptedNote | DroppedNote | null>;
}

/**
 * Why an opened note was not stored (#720 R1/R9). 'unverified' = the sender could not be authenticated (so no fingerprint is carried: F3);
 * 'not-in-book', 'ratchet-unopenable' (the frame's fault) and 'ratchet-local' (this device's fault: HELD, not acked) happen only AFTER
 * authentication, so `fp` is trustworthy there.
 */
export interface DroppedNote {
  dropped: 'unverified' | 'not-in-book' | 'ratchet-unopenable' | 'ratchet-local' | 'ratchet-desync';
  fp?: string;
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

/**
 * THE ONE ACK DOOR (#720 R1). consume never asks the relay to delete an envelope that did not become a stored message unless a
 * metadata-only record of it was committed FIRST. `record` THROWS if it cannot commit (store locked, write failed): the envelope then
 * stays on the relay. `clear` removes the record of an envelope that has since opened (R5), and also throws on failure.
 * Omit the sink and consume behaves as before (no records): the headless agent path, which has no IndexedDB.
 */
export interface DeadLetterSink {
  record(row: DeadLetterRow): Promise<DeadLetterRow>;
  clear(envelopeId: string): Promise<void>;
  /** Once per poll, after records were written (retention pruning). Best effort: a failure here never affects what is acked. */
  settle?(): Promise<void>;
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
  openLegs?: OpenLegCounter; // #720: the counter the openers bump; consume reads it per poll (omit = opened_* stay 0)
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
  deadLetter?: DeadLetterSink; // #720: record-before-ack for everything that did not become a stored message
}

export interface ConsumeSummary {
  polled: number;
  applied: number;
  ignited: number;
  notes: number; // over-wire notes persisted to the inbox (distinct from contact-book applies)
  delivered: number; // delivery receipts verified → outbound notes marked delivered (the "Delivered" graduation)
  dropped: number; // rejected/undecryptable/not-in-book — silently
  held: number; // #720: hybrid packages KEPT on the relay because no kem secret is derivable yet (also counted in `dropped`, as before)
  deadLettered: number; // #720: terminal envelopes whose metadata record was committed, then acked
  unrecorded: number; // #720: terminal/opened envelopes NOT acked because their record could not be committed (or cleared): left on the relay
  /**
   * #720 ruling (c): how many envelopes THIS poll consumed as a LOSS (not a message, not benign), per reason. Counted when the envelope enters
   * the ack list, so it is exactly once per envelope even if its record failed on an earlier poll, and it counts WITHOUT a sink: headless
   * pollers (no IndexedDB, no records) still see their losses. Counts only, never an id. Held envelopes count as 'missing-key' only when released.
   */
  lost: Partial<Record<DeadLetterReason, number>>;
  /**
   * #720 (Archie #2032, Flint #2031): how many opens this poll succeeded on each LEG of the dual-read opener. The classical leg is a
   * compatibility fallback that may only be removed once every active sender shows 0 here over 7 days. Counts only, snake_case on purpose
   * (the ward allowlist in devin_quarantine names exactly these keys). Always present; 0 when no counter was wired.
   */
  opened_hybrid: number;
  opened_classical: number;
  released: number; // #720: held envelopes past the keep bound (50 / 7 days): their record was committed, then they were acked
  acked: number;
  rejected?: number; // HTTP status when the poll request itself was refused (e.g. 401 owner-auth); absent on a clean poll — a rejected poll is NOT an empty mailbox
}

/**
 * What a terminal outcome IS. `benign` = the content is already stored or it was never a message (named, test-pinned list in
 * dead-letter.ts): acked with no record. Anything else is a LOSS and gets a record committed before the ack.
 */
export type TerminalClass = { benign: BenignTerminal } | { reason: DeadLetterReason; fp?: string };

type Outcome =
  | { kind: 'applied'; event: LiveApplyEvent }
  | { kind: 'note'; event: NoteLiveEvent } // over-wire note persisted → ack + inbox repaint (NOT a book beat)
  | { kind: 'receipt'; event: ReceiptLiveEvent } // delivery receipt verified → note marked delivered → ack + inbox repaint
  | { kind: 'terminal'; cls: TerminalClass } // permanently invalid (bad sig, stale, not-for-me, not-in-book) → ack, after its record if it is a loss
  | { kind: 'retryable' } // e.g. epoch-ahead-needs-lineage → leave for a later poll after lineage catch-up
  | { kind: 'held'; reason?: 'missing-key' | 'ratchet-local' | 'ratchet-desync'; fp?: string }; // #720: a hybrid package this owner cannot open YET (no derivable kem secret): retryable AND counted, so the UI can say so

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
  const summary: ConsumeSummary = { polled: 0, applied: 0, ignited: 0, notes: 0, delivered: 0, dropped: 0, held: 0, deadLettered: 0, unrecorded: 0, released: 0, lost: {}, opened_hybrid: 0, opened_classical: 0, acked: 0 };
  deps.openLegs?.take(); // discard anything counted outside a poll: a poll reports only its own opens

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

  // 2) Consume each envelope independently; flush acks in 20-id chunks so
  //    (a) no /ack header ever crosses the ~16KB HTTP 431 edge cap, and
  //    (b) a deep backlog drains incrementally even under a 55s poll timeout.
  const ACK_CHUNK = 20;
  const flushAckChunk = async (chunk: string[]) => {
    if (chunk.length === 0 || deps.owner.cycle?.ended) return;
    const ackHeaders = await signMailboxAckRequest({
      mailboxId,
      envelopeIds: chunk,
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
      body: JSON.stringify({ mailbox_id: mailboxId, envelope_ids: chunk }),
    });
    if (ackRes.ok) summary.acked += chunk.length;
  };
  // Nothing is added to `toAck` in the consume loop itself: each envelope that may be acked goes through THE ACK DOOR below, which decides
  // WHAT must happen first (#720 R1: no ack of an envelope that did not become a stored message without a committed record of it).
  type Need = 'none' | 'clear' | { reason: DeadLetterReason; fp?: string };
  const heldNow: Array<{ id: string; blob: string; expiresAt: unknown; reason: 'missing-key' | 'ratchet-local' | 'ratchet-desync'; fp?: string }> = [];
  const sink = deps.deadLetter;
  const toAck: string[] = [];
  const bump = (r: DeadLetterReason) => {
    summary.lost[r] = (summary.lost[r] ?? 0) + 1;
  };

  // THE ACK DOOR. Run inline, one envelope at a time, so #307's incremental chunked drain keeps working. Without a sink (headless) behaviour
  // is as before: every consumed envelope is acked. With one, an envelope is acked only after its record is committed (a loss) or its stale
  // record is cleared (it opened). A failure keeps the envelope on the relay.
  const door = async (item: { id: string; blob: string; need: Need }): Promise<void> => {
    if (deps.owner.cycle?.ended) return; // the key may already be dropped: decide nothing, leave everything on the relay
    if (!sink || item.need === 'none') {
      if (item.need !== 'none' && item.need !== 'clear') bump(item.need.reason); // consumed as a loss with no record (headless)
      toAck.push(item.id);
    } else if (item.need === 'clear') {
      try {
        await sink.clear(recordKeyFor(item.id) ?? item.id); // R5: the message replaces its flag; an envelope that is stored but whose old record cannot be cleared retries
        toAck.push(item.id);
      } catch (err) {
        summary.unrecorded++;
        console.error('[return-channel] could not clear a dead-letter record (envelope left for retry):', err instanceof Error ? err.message : 'error');
      }
    } else {
      // E1: an unsafe (attacker-chosen) id is recorded under a DERIVED safe key and the ORIGINAL id is acked, so it can neither be lost
      // unrecorded nor sit on the relay filling the mailbox. A row that cannot be built at all (not a string, an unreadable time) stays on the relay.
      const key = recordKeyFor(item.id);
      const row = key ? makeDeadLetterRow({ envelopeId: key, firstSeen: now(), reason: item.need.reason, blob: item.blob, fp: item.need.fp }) : null;
      if (!row) {
        summary.unrecorded++;
        return;
      }
      try {
        await sink.record(row);
        summary.deadLettered++;
        bump(item.need.reason);
        toAck.push(item.id);
      } catch (err) {
        summary.unrecorded++;
        console.error('[return-channel] could not commit a dead-letter record (envelope left on the relay):', err instanceof Error ? err.message : 'error');
      }
    }
  };

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
      await door({ id: env.envelope_id, blob: env.blob, need: 'clear' });
      try {
        deps.emit?.(outcome.event);
      } catch {
        /* the live-beat is best-effort; a repaint failure must not block consume/ack */
      }
    } else if (outcome.kind === 'note') {
      summary.notes++;
      await door({ id: env.envelope_id, blob: env.blob, need: 'clear' }); // persisted to the inbox → consumed; a record from an earlier poll is cleared
      try {
        deps.emitNote?.(outcome.event);
      } catch {
        /* inbox repaint is best-effort; a repaint failure must not block consume/ack */
      }
    } else if (outcome.kind === 'receipt') {
      summary.delivered++;
      await door({ id: env.envelope_id, blob: env.blob, need: 'clear' }); // note marked delivered → consumed
      try {
        deps.emitReceipt?.(outcome.event);
      } catch {
        /* inbox delivered-repaint is best-effort; a repaint failure must not block consume/ack */
      }
    } else if (outcome.kind === 'terminal') {
      summary.dropped++;
      // A benign terminal is consumed with no record; anything else is a LOSS and needs its record first.
      await door({ id: env.envelope_id, blob: env.blob, need: 'benign' in outcome.cls ? 'none' : outcome.cls });
    } else if (outcome.kind === 'held') {
      heldNow.push({ id: env.envelope_id, blob: env.blob, expiresAt: env.expires_at, reason: outcome.reason ?? 'missing-key', fp: outcome.fp });
      summary.dropped++; // unchanged accounting: a held blob has always counted as not-consumed this poll
    } else {
      summary.dropped++; // retryable — leave in the mailbox for a later poll
    }
    if (toAck.length >= ACK_CHUNK) {
      const batch = toAck.splice(0, ACK_CHUNK);
      await flushAckChunk(batch);
    }
  }


  // Held envelopes (kept on the relay for retry): each gets a record so its FIRST-SEEN time survives across polls, then the keep bound
  // applies (<= 50 and <= 7 days; the OLDEST are released). A released envelope's record is already committed, so it is acked now.
  const stillHeld: typeof heldNow = [];
  if (sink && !deps.owner.cycle?.ended) {
    const seen: Array<{ envelope_id: string; first_seen: string; group: string }> = [];
    const byId = new Map(heldNow.map((h) => [h.id, h]));
    const idByKey = new Map<string, string>(); // record key -> the id the relay knows (they differ only for an unsafe id, E1)
    for (const h of heldNow) {
      const key = recordKeyFor(h.id);
      const row = key ? makeDeadLetterRow({ envelopeId: key, firstSeen: now(), reason: h.reason, blob: h.blob, fp: h.fp }) : null;
      if (!row || !key) continue; // not a string: cannot be recorded or bounded; it stays on the relay
      try {
        const saved = await sink.record(row);
        idByKey.set(key, h.id);
        // #720 r2 (Flint, B1 for holds): an admitted contact's LOCAL frame is bounded only against that contact's own; 'missing-key' holds
        // (outsider-depositable while this device has no kem secret) share their own group. A group may only push out its own.
        const group = h.reason === 'missing-key' ? 'missing-key' : `${h.reason}:${(h.fp ?? '').toLowerCase()}`; // each ratchet class is bounded per contact, apart from the others
        seen.push({ envelope_id: saved.envelope_id, first_seen: saved.first_seen, group });
      } catch {
        /* cannot record this poll: it stays on the relay, unbounded for now; retried next poll */
      }
    }
    const groups = new Map<string, typeof seen>();
    for (const r of seen) groups.set(r.group, [...(groups.get(r.group) ?? []), r]);
    const release = [...groups.values()].flatMap((g) => planBound(g, Date.parse(now())).release);
    const released = new Set(release.flatMap((r) => idByKey.get(r.envelope_id) ?? []));
    for (const id of released) {
      toAck.push(id);
      summary.released++;
      bump(byId.get(id)?.reason ?? 'missing-key'); // a released LOCAL ratchet frame counts as 'ratchet-local', apart from the sender-side 'ratchet-unopenable'
    }
    for (const h of byId.values()) if (!released.has(h.id)) stillHeld.push(h);
  } else {
    stillHeld.push(...heldNow);
  }
  summary.held = stillHeld.length;
  if (sink?.settle && (summary.deadLettered > 0 || heldNow.length > 0)) {
    try {
      await sink.settle();
    } catch {
      /* retention is housekeeping; it must not affect consume or ack */
    }
  }

  // #720: report how many blobs are being KEPT because this device cannot open them yet. Reported on every CLEAN poll, including 0, so a
  // notice clears once they open or expire. NOT reported when the poll was refused (returned above) or the unlock cycle ended mid-tick:
  // in both the state of the mailbox is unknown, and an unknown state must neither raise nor clear the notice.
  if (!deps.owner.cycle?.ended) {
    try {
      deps.emitHeld?.(summary.held, { expiresAt: earliestExpiry(stillHeld.map((h) => h.expiresAt)) });
    } catch {
      /* the notice is best-effort; a repaint failure must not block consume/ack */
    }
  }

  // 3) Ack-delete any remaining terminal envelopes (owner-signed), in chunks. apply is idempotent, so a crash before ack
  //    just redelivers and re-applies harmlessly (at-least-once). Cycle ended mid-tick: flushAckChunk skips (it can't be signed).
  while (toAck.length > 0 && !deps.owner.cycle?.ended) {
    const batch = toAck.splice(0, ACK_CHUNK);
    await flushAckChunk(batch);
  }

  if (deps.openLegs) {
    const legs = deps.openLegs.take();
    summary.opened_hybrid = legs.hybrid;
    summary.opened_classical = legs.classical;
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
          : { kind: 'terminal', cls: { benign: 'joiner-already-known' } };
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
        if (accepted && 'dropped' in accepted) {
          // 'unverified' = the sender was never authenticated: no fingerprint travels with it (F3). The other two come after authentication.
          if (accepted.dropped === 'unverified') return { kind: 'terminal', cls: { reason: 'verify-failed' } };
          // v5.3 (Flint #2052): a ratchet frame this DEVICE could not open is HELD (kept on the relay, recorded at first sight, bounded), never acked as the sender's fault.
          if (accepted.dropped === 'ratchet-local' || accepted.dropped === 'ratchet-desync') return { kind: 'held', reason: accepted.dropped, fp: accepted.fp };
          return { kind: 'terminal', cls: { reason: accepted.dropped === 'not-in-book' ? 'not-in-book' : 'ratchet-unopenable', fp: accepted.fp } };
        }
        // A plain null is a legacy drop with no reason: recorded as the conservative 'verify-failed' (never silent, never a named sender).
        return accepted
          ? { kind: 'note', event: { note_id: accepted.note_id, thread_id: accepted.thread_id, from_fingerprint: accepted.from_fingerprint } }
          : { kind: 'terminal', cls: { reason: 'verify-failed' } };
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
          : { kind: 'terminal', cls: { benign: 'receipt-no-match' } };
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
    return { kind: 'terminal', cls: { reason: classifyBlob(blob) === 'other' ? 'unknown-format' : 'decrypt-failed' } };
  }
  if (!signed || typeof signed.envelope?.fingerprint !== 'string') {
    return { kind: 'terminal', cls: { reason: classifyBlob(blob) === 'other' ? 'unknown-format' : 'decrypt-failed' } };
  }

  // whitelist-on-fetch (I-2): an update from a fingerprint not in the book is dropped unread.
  // The sender is NOT authenticated here (verify has not run), so the record carries no fingerprint (F3).
  const contact = await deps.store.lookup(signed.envelope.fingerprint);
  // Flint ruling (a): this is a NON-MESSAGE frame from a stranger. It is RECORDED (never a silent loss) but under its own reason, so it can
  // never raise an "N messages couldn't be verified" count and never lands in a message budget.
  if (!contact) return { kind: 'terminal', cls: { reason: 'unverified-frame' } };

  // verify — the one gate. epoch-ahead needs lineage catch-up first → retryable; all else terminal.
  let verified;
  try {
    verified = await verifyIncomingContactUpdate(signed, contact.known);
  } catch (e) {
    const retryable = e instanceof ContactUpdateRejected && e.reason === 'epoch-ahead-needs-lineage';
    return retryable ? { kind: 'retryable' } : { kind: 'terminal', cls: { reason: 'unverified-frame' } }; // same class as a stranger frame (ruling a)
  }

  // apply — pure living-wins over the current record. stale-version = already applied → terminal.
  let applied;
  try {
    applied = applyVerifiedContactUpdate(contact.current, verified, now());
  } catch (e) {
    if (e instanceof ContactUpdateApplyRejected) return { kind: 'terminal', cls: { benign: 'contact-update-stale' } };
    throw e; // an unexpected (non-ApplyRejected) error → propagates to the guarded consume loop (wedge-immune)
  }

  // persist may throw on a store I/O failure — that too propagates to the guarded loop (retryable).
  if (dead()) return { kind: 'retryable' };
  await deps.store.persist(contact.current.id, applied.next);
  return { kind: 'applied', event: { id: contact.current.id, fingerprint: signed.envelope.fingerprint, ignited: applied.ignited } };
}
