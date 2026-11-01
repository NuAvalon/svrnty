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
} from '@/lib/sync/consume-mailbox';
import { openpgpEnvelopeDecryptor, parseContactUpdateWire } from '@/lib/sync/contact-update-envelope';
import { noteOpenpgpDecryptor, sealNoteTo, parseNoteWire } from '@/lib/messaging/seal';
import { verifyNoteSender, signNoteWire } from '@/lib/messaging/note-auth';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { noteRewriteRefused } from '@/lib/messaging/rewrite-refused';
import { admitContact } from '@/lib/trust/admit-contact';
import { headlessDeadLetterSink } from './headless-dead-letter';
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
function buildNoteSeam(owner: HeadlessOwner, store: HeadlessStore, now: () => string, hybrid?: LivingBookHybridSecrets, legs?: OpenLegCounter): NoteResponseSeam {
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
export async function buildHeadlessConsumeDeps(owner: HeadlessOwner, store: HeadlessStore, opts: HeadlessOpts = {}): Promise<ConsumeDeps> {
  const now = () => new Date().toISOString();
  // Derive THIS owner's hybrid OPEN-material from the custody-threaded ML-KEM secret (OwnerIdentity.kemSecretKey,
  // ① — the SAME helper + B64 contract the FE path uses). undefined for a classical identity OR when the secret
  // is absent/un-derivable (① pending / wrong-length) → classical-only openers + the ③ loud-retry gate below.
  // Headless key lifetime = PROCESS lifetime: the owner object holds the passphrase and the kem secret (base64) for the
  // whole run, so this is derived per poll and its bytes are not zeroed. No tick-scope claim here (that is the FE poll).
  const hybrid = await deriveOwnerHybridSecrets(owner.privateKeyArmored, owner.passphrase, owner.kemPublicKey, owner.kemSecretKey);
  const classicalCU = openpgpEnvelopeDecryptor(owner.privateKeyArmored, owner.passphrase);
  const legs = createOpenLegCounter(); // #720: opened_hybrid / opened_classical per poll (counts only)
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
    note: buildNoteSeam(owner, store, now, hybrid, legs),
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
  };
}

function deadline(opts: HeadlessOpts): (() => boolean) | undefined {
  if (opts.budgetMs === undefined) return undefined;
  const clock = opts.nowMs ?? Date.now;
  const end = clock() + opts.budgetMs;
  return () => clock() >= end;
}

/** Poll the owner's smart mailbox ONCE: decrypt → verify → apply → persist → ack every pending envelope. */
export async function pollHeadlessOnce(owner: HeadlessOwner, store: HeadlessStore, opts: HeadlessOpts = {}): Promise<ConsumeSummary> {
  return consumeInboundContactUpdates(await buildHeadlessConsumeDeps(owner, store, opts));
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
 * Seal-only sibling of sendNoteFromHeadless (dh-fleet-comms §route R-1): sign → seal → persist the
 * local outbound copy — WITHOUT the relay deposit. Returns the sealed wire form so a transport
 * router can carry the SAME blob on whichever route it picks (local unix intake or relay envelope
 * POST); the route choice never changes the bytes. The sealNoteTo blob is the ONLY form that leaves
 * the device — never a local plaintext variant.
 *
 * Same fail-closed HNDL contract: a recipient with no verified pq_kem yields blob:null (never a
 * classical downgrade); the local copy is still kept as "not sent".
 */
export async function sealNoteFromHeadless(args: {
  owner: HeadlessOwner;
  senderKind?: ParticipantKind;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  /** Recipient's verified ML-KEM-1024 pubkey (base64). Present ⇒ PQ-hybrid seal (HNDL); ABSENT ⇒
   *  fail-closed: blob:null (never downgraded to classical), local copy kept as not-sent. */
  peerPqKemPublicKey?: string;
  /** dual-seal-interim-001 is RETIRED on this build: dev seals no classical notes (no downgrade) and every dev consumer dual-reads, which
   *  was the interim's end condition. Kept only so old callers still type-check; true just logs a warning. NO classical copy is ever made. */
  dualSeal?: boolean;
  /** Internal (sendNoteFromHeadless): return the local outbound record instead of writing it, so the relay send keeps dev's order
   *  seal → deposit → local copy (a save that fails AFTER a deposit reports DEPOSITED, never NOT SENT; peer-kem.test pins it). */
  deferLocalCopy?: boolean;
  body: string;
  threadId?: string;
  store: HeadlessStore;
  noteId?: string; // inject for determinism in tests
  sentAt?: string; // inject for determinism in tests
}): Promise<{ note_id: string; thread_id: string; blob: string | null; localCopy?: NoteRecord }> {
  const now = () => new Date().toISOString();
  const thread_id = args.threadId ?? `thr_${args.owner.fingerprint.slice(0, 6)}_${args.peerFingerprint.slice(0, 6)}`;
  const note_id = args.noteId ?? `note_${globalThis.crypto.randomUUID()}`;
  const sent_at = args.sentAt ?? now();

  const unsigned: NoteWireV0 = {
    type: NOTE_WIRE_TYPE,
    note_id,
    thread_id,
    from_fingerprint: args.owner.fingerprint,
    sent_at,
    body: args.body,
    participant_kind: args.senderKind ?? 'agent',
  };
  const wire = await signNoteWire(
    unsigned,
    args.owner.publicKeyArmored,
    args.owner.privateKeyArmored,
    args.owner.passphrase,
    args.owner.kemPublicKey,
    args.owner.sigPublicKey,
  );
  // fail-closed (HNDL): seal PQ-hybrid ONLY when the recipient has a verified ML-KEM-1024 pubkey —
  // never a silent classical downgrade. The local outbound copy is kept either way.
  let blob: string | null = null;
  if (args.peerPqKemPublicKey) {
    blob = await sealNoteTo(wire, args.peerPublicKeyArmored, args.peerPqKemPublicKey);
    if (args.dualSeal) {
      // dual-seal-interim-001 was "while canon lacks the dual-read consume leg". Dev has dual-read (hybrid-first + classical fallback in
      // every consumer) and seal.ts no longer seals classical notes at all (no classical downgrade, Flint). So on dev the interim is
      // retired: the hybrid deposit goes out as usual, the classical copy is skipped, and the send never fails because of it.
      console.warn('[headless-notes] dualSeal requested but retired on this build (receivers dual-read); hybrid only');
    }
  } else {
    console.warn('[headless-notes] fail-closed: recipient has no pq_kem — note NOT sealed (never downgrade, HNDL)');
  }

  // local outbound copy (Node store)
  const localCopy: NoteRecord = {
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
  };
  if (args.deferLocalCopy) return { note_id, thread_id, blob, localCopy };
  args.store.putNote(localCopy);
  return { note_id, thread_id, blob };
}

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
  /** dual-seal-interim-001 is RETIRED on this build: dev seals no classical notes (no downgrade) and every dev consumer dual-reads, which
   *  was the interim's end condition. Kept only so old callers still type-check; true just logs a warning. NO classical copy is ever made. */
  dualSeal?: boolean;
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
  // Seal via the sibling (sign → seal → local copy); deposit the SAME blob the
  // seal-only path would hand a router (R-1). blob:null = the HNDL fail-closed
  // (no verified peer kem) — NOT deposited, never downgraded to classical.
  const sealed = await sealNoteFromHeadless({ ...args, deferLocalCopy: true });
  let deposited = false;
  if (sealed.blob !== null) {
    const mailbox_id = deriveMailboxId(args.peerFingerprint);
    const res = await fetchImpl(`${relayBase}/envelope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mailbox_id, blob: sealed.blob }),
    });
    deposited = res.ok;
  }
  // dev's order: the local outbound copy is written AFTER the deposit (kept as "not sent" when not deposited). If this write throws after a
  // successful deposit, the CLI reports DEPOSITED-but-save-failed and tells the caller not to resend.
  if (sealed.localCopy) args.store.putNote(sealed.localCopy);
  return { note_id: sealed.note_id, thread_id: sealed.thread_id, deposited };
}
