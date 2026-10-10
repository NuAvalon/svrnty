// src/lib/headless/headless-client.ts
// The RUNTIME half of L2b: a headless (CLI/docker) svrnty client that RECEIVES (polls the smart mailbox,
// decrypts → verifies → applies the inbound types) and SENDS (notes + trust-affirmations) — no browser,
// no IndexedDB. It reuses the storage-agnostic consume core (consume-mailbox.ts) + the pure-crypto seams
// (openpgpEnvelopeDecryptor / noteOpenpgpDecryptor / trustAffirmOpenpgpDecryptor / verifyNoteSender /
// acceptTrustAffirm); the browser-only persistence is replaced by HeadlessStore.
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
  type TrustAffirmResponseSeam,
} from '@/lib/sync/consume-mailbox';
import { openpgpEnvelopeDecryptor } from '@/lib/sync/contact-update-envelope';
import { noteOpenpgpDecryptor, sealNoteTo } from '@/lib/messaging/seal';
import { verifyNoteSender, signNoteWire } from '@/lib/messaging/note-auth';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { trustAffirmOpenpgpDecryptor } from '@/lib/trust/trust-affirm-seal';
import { acceptTrustAffirm } from '@/lib/trust/trust-affirm-consume';
import { sendTrustAffirmToPeer } from '@/lib/trust/trust-affirm-transport';
import { edgeTrusted } from '@/lib/trust/contact-edge';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore } from './headless-store';
import type { NoteWireV0, NoteRecord, NoteThread, ParticipantKind } from '@/lib/messaging/types';

/** The headless owner's unlocked key material — same shape the consume core signs poll/ack with. */
export type HeadlessOwner = OwnerIdentity;

export interface HeadlessOpts {
  relayBase?: string; // default '/api/relay'
  fetchImpl?: typeof fetch; // default global fetch (inject for tests)
}

// ── the over-wire NOTE seam, Node-backed (mirrors live-book-poll.buildNoteSeam + acceptInboundNote) ──
function buildNoteSeam(owner: HeadlessOwner, store: HeadlessStore, now: () => string): NoteResponseSeam {
  const decryptNote = noteOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase);
  return {
    verify: (blob) => decryptNote(blob),
    accept: async (wire: NoteWireV0) => {
      // authenticate (public_key↔from_fingerprint + sig) BEFORE admit — a note is forgeable until verified.
      if (!(await verifyNoteSender(wire))) return null; // unsigned / forged — silent drop
      if (!store.getContactByFingerprint(wire.from_fingerprint)) return null; // stranger — silent drop (I-2)
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
      store.putNote(rec); // throws → consumeOne treats as retryable (ack-follows-persist)
      const existing = store.listThreads().find((t) => t.thread_id === rec.thread_id);
      const thread: NoteThread = existing
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
      store.putThread(thread);
      return { note_id: rec.note_id, thread_id: rec.thread_id, from_fingerprint: rec.from_fingerprint };
    },
  };
}

// ── the mutual-trust AFFIRMATION seam, Node-backed (acceptTrustAffirm is already injection-based) ──
function buildTrustAffirmSeam(owner: HeadlessOwner, store: HeadlessStore, now: () => string): TrustAffirmResponseSeam {
  const decryptAffirm = trustAffirmOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase);
  return {
    verify: (blob) => decryptAffirm(blob),
    accept: (wire) =>
      acceptTrustAffirm({
        wire,
        ownerFingerprint: owner.fingerprint,
        isAdmitted: async (fp) => store.getContactByFingerprint(fp) != null, // FALSE-MUTUAL gate (in-book)
        applyMutual: async (fromFp, trusts) => {
          const rec = store.getContactByFingerprint(fromFp);
          if (!rec) throw new Error('headless applyMutual: contact vanished between admit and apply');
          const iTrustThem = edgeTrusted(rec); // reciprocal reads MY existing trusted state — no wire promotion
          const mutual = { they_trust_me: trusts, last_sync: now(), reciprocal: iTrustThem && trusts };
          store.updateContact(rec.id, { mutual });
          return { id: rec.id, reciprocal: mutual.reciprocal };
        },
      }),
  };
}

/**
 * Assemble the consume deps for a headless owner over a HeadlessStore. The joiner (Grow-gate) seam is
 * omitted — headless agents don't run the browser Grow flow; contact-update + note + affirm cover receive.
 */
export function buildHeadlessConsumeDeps(owner: HeadlessOwner, store: HeadlessStore, opts: HeadlessOpts = {}): ConsumeDeps {
  const now = () => new Date().toISOString();
  return {
    owner,
    decrypt: openpgpEnvelopeDecryptor(owner.privateKeyArmored, owner.passphrase),
    store: store.asContactStore(),
    note: buildNoteSeam(owner, store, now),
    affirm: buildTrustAffirmSeam(owner, store, now),
    relayBase: opts.relayBase,
    fetchImpl: opts.fetchImpl,
    now,
  };
}

/** Poll the owner's smart mailbox ONCE: decrypt → verify → apply → persist → ack every pending envelope. */
export async function pollHeadlessOnce(owner: HeadlessOwner, store: HeadlessStore, opts: HeadlessOpts = {}): Promise<ConsumeSummary> {
  return consumeInboundContactUpdates(buildHeadlessConsumeDeps(owner, store, opts));
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
// Trust-affirmations: reuse sendTrustAffirmToPeer (already Node-ready — pure sign→seal→POST, no store).
export { sendTrustAffirmToPeer };

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
  });
  return { note_id, thread_id, deposited };
}
