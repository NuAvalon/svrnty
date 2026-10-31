// src/lib/headless/headless-client.ts
// The RUNTIME half of L2b: a headless (CLI/docker) svrnty client that RECEIVES (polls the smart mailbox,
// decrypts → verifies → applies the inbound types) and SENDS notes — no browser,
// no IndexedDB. It reuses the storage-agnostic consume core (consume-mailbox.ts) + the pure-crypto seams
// (openpgpEnvelopeDecryptor / noteOpenpgpDecryptor / verifyNoteSender); the browser-only persistence is
// replaced by HeadlessStore. (The trust-affirmation wire was removed in #593.)
//
// Owner key material is an INPUT (OwnerIdentity) — this module is decoupled from WHERE the keys come from.
// The custody-store → OwnerIdentity adapter (Athena's custody lane) is the integration seam; a headless
// agent unlocks its MintSecret from custody and hands {fingerprint, pub, priv, passphrase, pq*} here.
//
// HEADLESS-ONLY (imports node:fs via HeadlessStore) — never import into the browser bundle.

import {
  consumeInboundContactUpdates,
  type ConsumeDeps,
  type ConsumeSummary,
  type OwnerIdentity,
  type NoteResponseSeam,
  type ReceiptResponseSeam,
} from '@/lib/sync/consume-mailbox';
import { openpgpEnvelopeDecryptor, parseContactUpdateWire } from '@/lib/sync/contact-update-envelope';
import { noteOpenpgpDecryptor, sealNoteTo, parseNoteWire } from '@/lib/messaging/seal';
import { verifyNoteSender, signNoteWire } from '@/lib/messaging/note-auth';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { noteRewriteRefused } from '@/lib/messaging/rewrite-refused';
import { admitContact } from '@/lib/trust/admit-contact';
import { headlessDeadLetterSink } from './headless-dead-letter';
import { emitDeliveredReceipt } from '@/lib/messaging/receipt-emit';
import { parseReceiptWireV1, type ReceiptWireV1 } from '@/lib/messaging/receipt-wire-v1';
import { newReceiptKey, receiptKeyFromHex, receiptKeyToHex, verifyReceiptTag } from '@/lib/crypto/receipt-mac';
// L7 single dual-read chokepoint (Option-B): the headless consume deps compose the SAME dualReadOpener
// (hybrid-first → classical) the FE buildConsumeDeps uses, off the owner's ML-KEM secret (custody ①).
import { makeHybridOpener, dualReadOpener } from '@/lib/sync/hybrid-dual-read';
import { counted, createOpenLegCounter, type OpenLegCounter } from '@/lib/sync/open-leg-counter';
import { openMailboxEnvelope } from '@/lib/crypto/mailbox-envelope';
import { deriveOwnerHybridSecrets } from '@/lib/crypto/living-book-receive';
import type { LivingBookHybridSecrets } from '@/lib/crypto/living-book-sleeve';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore } from './headless-store';
import type { NoteWireV0, NoteRecord, NoteThread, ParticipantKind } from '@/lib/messaging/types';

/** The headless owner's unlocked key material — same shape the consume core signs poll/ack with. */
export type HeadlessOwner = OwnerIdentity;

export interface HeadlessOpts {
  relayBase?: string; // default '/api/relay'
  fetchImpl?: typeof fetch; // default global fetch (inject for tests)
  budgetMs?: number; // #712: stop consuming after this long (between envelopes), so a deep backlog never meets the watchdog mid-write
  nowMs?: () => number; // clock for the budget (inject for tests); default Date.now
  /** #713: the agent dir's dead-letter file. Present → a loss is RECORDED (metadata row) before its envelope is acked, and a failed write
   *  leaves the envelope on the relay. Absent → the old behaviour: the loss is only counted (summary.lost). */
  deadLetterPath?: string;
}

// ── the over-wire NOTE seam, Node-backed (mirrors live-book-poll.buildNoteSeam + acceptInboundNote) ──
function buildNoteSeam(owner: HeadlessOwner, store: HeadlessStore, now: () => string, hybrid?: LivingBookHybridSecrets, legs?: OpenLegCounter, receipts?: ReceiptCandidates): NoteResponseSeam {
  // Single dual-read chokepoint (Option-B, mirrors FE buildNoteSeam): hybrid-FIRST (makeHybridOpener →
  // openMailboxEnvelope bound to MY secrets + parseNoteWire, the SAME type-gate the classical path uses →
  // no-cross-swallow unchanged), classical FALLBACK. Classical-only when the owner has no derivable hybrid
  // secret (classical identity, or custody ① pending — then the ③ gate leaves un-openable hybrid for retry).
  const classicalNote = noteOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase);
  const verifyNote = hybrid
    ? dualReadOpener<NoteWireV0>(
        counted(makeHybridOpener<NoteWireV0>((pkg) => openMailboxEnvelope(pkg, hybrid.secrets, hybrid.myFp), parseNoteWire), 'hybrid', legs),
        counted(classicalNote, 'classical', legs),
      )
    : counted(classicalNote, 'classical', legs);
  return {
    verify: (blob) => verifyNote(blob),
    accept: async (wire: NoteWireV0) => {
      // authenticate (public_key↔from_fingerprint + sig) BEFORE admit — a note is forgeable until verified.
      // #720 say-why, mirroring the FE seam (live-book-poll.ts): a DroppedNote carries the REASON, so the record is honest. A bare null was
      // recorded as 'verify-failed' for BOTH cases, which made a stranger's genuine note look like forged crypto (Peter→Athena 10-31).
      // No fingerprint travels with 'unverified' (from_fingerprint is attacker-controlled until verified: F3).
      if (!(await verifyNoteSender(wire))) return { dropped: 'unverified' }; // unsigned / forged
      const sent_at = wire.sent_at || now();
      const rec: NoteRecord = {
        note_id: wire.note_id,
        thread_id: wire.thread_id,
        direction: 'inbound',
        from_fingerprint: wire.from_fingerprint,
        to_fingerprints: [],
        sent_at,
        body: wire.body,
        participant_kind: wire.participant_kind || 'human',
        retention: { expires_at: null },
        wire_type: NOTE_WIRE_TYPE,
      };
      // in-book AND not-blocked (admitContact), checked on the copy the note is written to: a block that lands before the chunk
      // commit wins (#712 C2). A blocked sender reports 'not-in-book' too, as the FE does: no separate "blocked" reason leaves this device.
      // The fp is authenticated here (verifyNoteSender above). Throws → retryable (ack-follows-persist).
      const threadFor = (existing: NoteThread | undefined): NoteThread =>
        existing
          ? { ...existing, last_activity_at: sent_at }
          : {
              thread_id: rec.thread_id,
              kind: wire.ring_channel_id ? 'ring' : 'direct',
              participants: [
                { fingerprint: wire.from_fingerprint, kind: rec.participant_kind, display_name: wire.from_fingerprint.slice(0, 8) },
              ],
              ring_channel_id: wire.ring_channel_id,
              created_at: sent_at,
              last_activity_at: sent_at,
              retention: { expires_at: null },
            };
      const r = store.acceptInboundNote(rec, threadFor, admitContact);
      if (r === 'not-admitted') return { dropped: 'not-in-book', fp: wire.from_fingerprint };
      // Layer 1 R1: a NEW note, or a byte-identical redelivery (C2: our first receipt may have been lost while the sender's key is unspent),
      // is a receipt CANDIDATE. Never a FWW refusal ('kept'). Nothing is sent here: the note is durable only at its chunk commit, and the
      // emit must never hold the writer lock (C1). sendHeadlessReceipts() sends after the pass, for what the store then actually holds.
      if (r === 'stored') receipts?.set(`${wire.from_fingerprint}:${wire.note_id}`, wire);
      if (r === 'kept') {
        // FIRST WRITE WINS: a same-sender note that reuses a stored id with different content is refused; the stored note is what we acknowledge.
        noteRewriteRefused();
        const kept = store.listNotes().find((x) => x.note_id === rec.note_id && x.direction === 'inbound' && x.from_fingerprint === rec.from_fingerprint)!;
        return { note_id: kept.note_id, thread_id: kept.thread_id, from_fingerprint: kept.from_fingerprint };
      }
      return { note_id: rec.note_id, thread_id: rec.thread_id, from_fingerprint: rec.from_fingerprint };
    },
  };
}

/** Layer 1: receipt candidates collected during ONE poll, at most one per (sender fp, note_id). Holds the verified wire (never logged). */
export type ReceiptCandidates = Map<string, NoteWireV0>;

/**
 * Layer 1 S2 (spec v1 65bac8aa, Flint C1): the SENDER half of "Delivered" for a headless owner, mirroring live-book-poll.buildReceiptSeam.
 * Hybrid-only (a v1 receipt is never sealed classical), 'delivered' only, OUR outbound row with a stored key, verifyReceiptTag, then the row
 * becomes delivered with the key REMOVED, through the store's group commit (markDelivered → mutate → the #712 chunk write, never a separate
 * write per receipt). Anything else (unknown note, an inbound note with that id, no key, wrong code, forged / transplanted tag) → null: the
 * row and its key are untouched, so the real receipt can still land. A false "Delivered" is unreachable: markDelivered is called on ONE line.
 */
export function buildHeadlessReceiptSeam(owner: HeadlessOwner, store: HeadlessStore, hybrid?: LivingBookHybridSecrets, legs?: OpenLegCounter): ReceiptResponseSeam {
  const verifyReceipt = hybrid
    ? counted(makeHybridOpener<ReceiptWireV1>((pkg) => openMailboxEnvelope(pkg, hybrid.secrets, hybrid.myFp), parseReceiptWireV1), 'hybrid', legs)
    : async () => null;
  return {
    verify: (blob) => verifyReceipt(blob),
    accept: async (wire) => {
      if (wire.code !== 'delivered') return null; // the only code this build acts on; never 'read'
      const note = store.findOutboundNote(owner.fingerprint, wire.note_id);
      if (!note) return null; // unknown, or an inbound note that merely shares the id
      const rk = receiptKeyFromHex(note.receipt_key);
      if (!rk) return null; // no stored key (an older note, or already confirmed)
      const peerFp = note.to_fingerprints[0];
      if (!peerFp) return null;
      if (!verifyReceiptTag(rk, note.note_id, wire.code, wire.tag)) return null; // forged / transplanted / wrong code: the key survives
      store.markDelivered(owner.fingerprint, note.note_id); // ★ THE ONE LINE: verified → delivered, key dropped (group commit)
      return { note_id: note.note_id, thread_id: note.thread_id, from_fingerprint: peerFp };
    },
  };
}

/** Counts only (never an id, a key or a tag). */
export interface ReceiptSendSummary {
  sent: number;
  skipped: number;
  failed: number;
}

/**
 * Layer 1 R1, AFTER the poll (Flint C1/C2/C3): send the collected receipts. Called once the consume pass returned, so no chunk is open and
 * no writer lock is held by this process; each POST is bounded by emitDeliveredReceipt's 8 s timeout and they run concurrently (one wait).
 * A candidate gets a receipt only if, NOW:
 *  - the store holds that inbound note byte-identical to the wire (it was durably committed: a chunk whose write failed was rolled back, a
 *    note refused at the commit re-apply (C2) is not there, and a different-content redelivery (FWW) never became a candidate), and
 *  - its sender is admitted on this copy (C3: re-checked here, never trusted from the caller's order: a receipt to a stranger or a blocked
 *    sender would be a liveness oracle).
 * emitDeliveredReceipt itself refuses a kem-less sender (no downgrade) and a wire without a 64-hex receipt_key, and never throws.
 */
export async function sendHeadlessReceipts(store: HeadlessStore, candidates: ReceiptCandidates, opts: HeadlessOpts = {}): Promise<ReceiptSendSummary> {
  const out: ReceiptSendSummary = { sent: 0, skipped: 0, failed: 0 };
  const due: NoteWireV0[] = [];
  for (const wire of candidates.values()) {
    const held = store.listNotes().find((n) => n.direction === 'inbound' && n.note_id === wire.note_id && n.from_fingerprint === wire.from_fingerprint);
    const durable = !!held && held.body === wire.body && held.thread_id === wire.thread_id && held.sent_at === (wire.sent_at || held.sent_at);
    if (!durable || !admitContact(store.getContactByFingerprint(wire.from_fingerprint))) {
      out.skipped++;
      continue;
    }
    due.push(wire);
  }
  candidates.clear();
  const results = await Promise.all(due.map((w) => emitDeliveredReceipt(w, { fetchImpl: opts.fetchImpl, relayBase: opts.relayBase })));
  for (const r of results) out[r]++;
  return out;
}

/**
 * Assemble the consume deps for a headless owner over a HeadlessStore (ASYNC — it derives the owner's
 * hybrid open-material). The joiner (Grow-gate) seam is omitted — headless agents don't run the browser
 * Grow flow; contact-update + note cover receive (no affirm seam since #593).
 *
 * L7 HYBRID RECEIVE (single dual-read chokepoint, mirrors FE buildConsumeDeps): each of the 3 seams opens
 * hybrid-FIRST (dualReadOpener over makeHybridOpener, off the owner's ML-KEM secret) then falls back to
 * classical OpenPGP for in-flight legacy blobs. The owner's ML-KEM secret rides ON OwnerIdentity
 * (kemSecretKey, custody ① — headless has no browser vault/loadPQKeys), B64 → deriveOwnerHybridSecrets.
 *   • secret DERIVABLE ⇒ the hybrid path OPENS inbound hybrid mail; hybridSecretMissing=false.
 *   • secret ABSENT/un-derivable (classical identity, or custody ① pending) ⇒ classical-only openers, and
 *     hybridSecretMissing=true so Flint's ③ gate LEAVES an un-openable hybrid blob FOR RETRY (loud),
 *     never silently acked+dropped — the mail waits until the secret arrives, never vanishes.
 * The flag is keyed on ACTUAL derivability (not mere kem-pub presence) so a secret-HAVING agent never
 * loops its mail retryable-FOREVER (the flip-side harm Flint pinned, #168382).
 */
/** ConsumeDeps plus layer 1's post-pass receipt send. Call sendReceipts() AFTER consumeInboundContactUpdates(deps) returned. */
export type HeadlessConsumeDeps = ConsumeDeps & { sendReceipts: () => Promise<ReceiptSendSummary> };

export async function buildHeadlessConsumeDeps(owner: HeadlessOwner, store: HeadlessStore, opts: HeadlessOpts = {}): Promise<HeadlessConsumeDeps> {
  const now = () => new Date().toISOString();
  // Derive THIS owner's hybrid OPEN-material from the custody-threaded ML-KEM secret (OwnerIdentity.kemSecretKey,
  // ① — the SAME helper + B64 contract the FE path uses). undefined for a classical identity OR when the secret
  // is absent/un-derivable (① pending / wrong-length) → classical-only openers + the ③ loud-retry gate below.
  // Headless key lifetime = PROCESS lifetime: the owner object holds the passphrase and the kem secret (base64) for the
  // whole run, so this is derived per poll and its bytes are not zeroed. No tick-scope claim here (that is the FE poll).
  const hybrid = await deriveOwnerHybridSecrets(owner.privateKeyArmored, owner.passphrase, owner.kemPublicKey, owner.kemSecretKey);
  const classicalCU = openpgpEnvelopeDecryptor(owner.privateKeyArmored, owner.passphrase);
  const legs = createOpenLegCounter(); // #720: opened_hybrid / opened_classical per poll (counts only)
  const receipts: ReceiptCandidates = new Map();
  return {
    owner,
    openLegs: legs,
    // contact-update (the consume catch-all): single dual-read chokepoint — hybrid-first + classical fallback.
    decrypt: hybrid
      ? dualReadOpener(
          counted(makeHybridOpener((pkg) => openMailboxEnvelope(pkg, hybrid.secrets, hybrid.myFp), parseContactUpdateWire), 'hybrid', legs),
          counted(classicalCU, 'classical', legs),
        )
      : counted(classicalCU, 'classical', legs),
    store: store.asContactStore(),
    note: buildNoteSeam(owner, store, now, hybrid, legs, receipts),
    // Layer 1 S2: a verified receipt marks OUR outbound note delivered inside the poll's group commit
    receipt: buildHeadlessReceiptSeam(owner, store, hybrid, legs),
    // ③ loud-not-silent, keyed on ACTUAL derivability (Flint's hard gate #168382): advertise-kem-pub but the
    // ML-KEM secret did NOT derive ⇒ a hybrid blob is LEFT FOR RETRY, never silently acked+dropped. The instant
    // a derivable secret is present (① landed), this is FALSE → the dualReadOpener OPENS hybrid mail instead of
    // looping it retryable-FOREVER (the flip-side harm). advertise-kem && !hybrid ⟺ missing.
    hybridSecretMissing: !!owner.kemPublicKey && !hybrid,
    deadLetter: opts.deadLetterPath ? headlessDeadLetterSink(opts.deadLetterPath) : undefined,
    relayBase: opts.relayBase,
    fetchImpl: opts.fetchImpl,
    now,
    // #712: one store write per ack chunk, before its ack; a redelivered envelope the store already holds is acked unopened (C1)
    chunk: store.asChunkTxn(now),
    outOfTime: deadline(opts),
    sendReceipts: () => sendHeadlessReceipts(store, receipts, opts),
  };
}

function deadline(opts: HeadlessOpts): (() => boolean) | undefined {
  if (opts.budgetMs === undefined) return undefined;
  const clock = opts.nowMs ?? Date.now;
  const end = clock() + opts.budgetMs;
  return () => clock() >= end;
}

/** Poll the owner's smart mailbox ONCE: decrypt → verify → apply → persist → ack every pending envelope. */
export async function pollHeadlessOnce(owner: HeadlessOwner, store: HeadlessStore, opts: HeadlessOpts = {}): Promise<ConsumeSummary & { receipts_sent: number }> {
  const deps = await buildHeadlessConsumeDeps(owner, store, opts);
  const summary = await consumeInboundContactUpdates(deps);
  const r = await deps.sendReceipts(); // layer 1: after the pass, with no chunk open and no writer lock held
  return { ...summary, receipts_sent: r.sent };
}

export interface HeadlessPollHandle {
  stop: () => void;
}

/**
 * Start a background poll loop (default 1.5s, matching the browser live-book cadence). Non-overlapping +
 * fail-soft: a transient poll error is logged locally (never echoed — I-1) and retried next tick; one bad
 * tick can neither throw nor wedge the loop. Returns stop().
 */
export function startHeadlessPolling(
  owner: HeadlessOwner,
  store: HeadlessStore,
  opts: HeadlessOpts & { intervalMs?: number; onTick?: (s: ConsumeSummary) => void } = {},
): HeadlessPollHandle {
  const intervalMs = opts.intervalMs ?? 1_500;
  let stopped = false;
  let inFlight = false;
  const tick = async () => {
    if (stopped || inFlight) return;
    inFlight = true;
    try {
      const summary = await pollHeadlessOnce(owner, store, opts);
      opts.onTick?.(summary);
    } catch (err) {
      console.error('[headless-poll] tick failed (will retry):', err);
    } finally {
      inFlight = false;
    }
  };
  const timer = setInterval(() => void tick(), intervalMs);
  (timer as unknown as { unref?: () => void }).unref?.(); // don't keep the process alive on this alone
  void tick(); // immediate first poll
  return {
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}

// ── SEND ──────────────────────────────────────────────────────────────────────────────────────────

/**
 * Send an over-wire note from a headless client: sign → seal → deposit to the peer's mailbox, and persist
 * the outbound copy to the local HeadlessStore. Mirrors messaging/transport.sendNoteToPeer but writes the
 * local copy to the Node store (sendNoteToPeer persists to the browser IndexedDB notes store).
 *
 * HNDL (L7): the seal is PQ-hybrid (living-book-sleeve, X25519+ML-KEM-1024) when the recipient's ML-KEM
 * pubkey is supplied — the same fail-closed contract as transport.sendNoteToPeer: a recipient with no
 * verified pq_kem is NOT deposited to (never a silent classical downgrade); the local copy is kept as
 * "not sent" (deposited:false). So an agent's outbound mail is all-hybrid, and legacy/keyless peers are
 * skipped loud-locally, never downgraded.
 */
export async function sendNoteFromHeadless(args: {
  owner: HeadlessOwner;
  senderKind?: ParticipantKind;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  /** Recipient's verified ML-KEM-1024 pubkey (base64). Present ⇒ PQ-hybrid seal (HNDL); ABSENT ⇒
   *  fail-closed: NOT deposited (never downgraded to classical), local copy kept as not-sent. */
  peerPqKemPublicKey?: string;
  body: string;
  threadId?: string;
  store: HeadlessStore;
  relayBase?: string;
  fetchImpl?: typeof fetch;
  noteId?: string; // inject for determinism in tests
  sentAt?: string; // inject for determinism in tests
}): Promise<{ note_id: string; thread_id: string; deposited: boolean }> {
  const fetchImpl = args.fetchImpl ?? fetch;
  const relayBase = args.relayBase ?? '/api/relay';
  const now = () => new Date().toISOString();
  const thread_id = args.threadId ?? `thr_${args.owner.fingerprint.slice(0, 6)}_${args.peerFingerprint.slice(0, 6)}`;
  const note_id = args.noteId ?? `note_${globalThis.crypto.randomUUID()}`;
  const sent_at = args.sentAt ?? now();

  // Layer 1 S1 (mirrors transport.ts): a per-note freshness nonce + a fresh 32-byte receipt KEY, minted BEFORE signing so both are under the
  // sender's signature and inside the sealed wire. The key is kept ONLY on our outbound row below (store.json: the bodies' protection) and
  // is dropped when a verified receipt lands; it is never printed, journaled, dead-lettered or trailed.
  const receipt_nonce = Array.from(globalThis.crypto.getRandomValues(new Uint8Array(16)), (x) => x.toString(16).padStart(2, '0')).join('');
  const receipt_key = receiptKeyToHex(newReceiptKey());
  const unsigned: NoteWireV0 = {
    type: NOTE_WIRE_TYPE,
    note_id,
    thread_id,
    from_fingerprint: args.owner.fingerprint,
    sent_at,
    body: args.body,
    participant_kind: args.senderKind ?? 'agent',
    receipt_nonce,
    receipt_key,
  };
  const wire = await signNoteWire(
    unsigned,
    args.owner.publicKeyArmored,
    args.owner.privateKeyArmored,
    args.owner.passphrase,
    args.owner.kemPublicKey,
    args.owner.sigPublicKey,
  );
  // fail-closed (HNDL): seal PQ-hybrid + deposit ONLY when the recipient has a verified ML-KEM-1024 pubkey.
  // A recipient without one is NOT deposited to in a classical/downgraded form (never downgrade). The local
  // outbound copy is kept either way — sent ⇒ deposited:true; skipped ⇒ kept as "not sent", deposited:false.
  // Identical contract to messaging/transport.sendNoteToPeer so FE + headless sends behave the same.
  let deposited = false;
  if (args.peerPqKemPublicKey) {
    const blob = await sealNoteTo(wire, args.peerPublicKeyArmored, args.peerPqKemPublicKey);
    const mailbox_id = deriveMailboxId(args.peerFingerprint);
    const res = await fetchImpl(`${relayBase}/envelope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mailbox_id, blob }),
    });
    deposited = res.ok;
  } else {
    console.warn('[headless-notes] fail-closed: recipient has no pq_kem — note NOT deposited (never downgrade, HNDL)');
  }

  // local outbound copy (Node store)
  args.store.putNote({
    note_id,
    thread_id,
    direction: 'outbound',
    from_fingerprint: args.owner.fingerprint,
    to_fingerprints: [args.peerFingerprint],
    sent_at,
    body: args.body,
    participant_kind: args.senderKind ?? 'agent',
    retention: { expires_at: null },
    wire_type: NOTE_WIRE_TYPE,
    receipt_nonce,
    // only a deposited note can ever be confirmed; a fail-closed (not sent) copy keeps no key
    ...(deposited ? { receipt_key } : {}),
  });
  return { note_id, thread_id, deposited };
}
