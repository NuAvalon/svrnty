// src/lib/sync/live-book-poll.ts
// The RUNTIME poll call-site for the living address book (demo-spine beat-4).
//
// consumeInboundContactUpdates is deliberately seam-injected so it stays IndexedDB-free and
// crypto-agnostic. This module is the one place those seams are bound to the real client runtime, and
// the poll loop that actually drives them:
//   • owner   — the unlocked local identity: fingerprint + armored public key (from `identity`) + the
//               private key + passphrase (from loadKey; null while the session is locked).
//   • decrypt — openpgpEnvelopeDecryptor bound to the owner's private key (the classical envelope;
//               the hybrid-PQ decryptor is a named upgrade that swaps here with zero caller change).
//   • store   — a client-store adapter: getContactByFingerprint → {known, current}; updateContact = persist.
//   • emit    — the live-beat seam: after a verified apply, emitContactChange({ids:[id],reason:'live-apply'})
//               so ContactManagement repaints the row data-live="push" — the honest beat-4 signal, which
//               can ONLY fire on an incoming apply (a local ui-edit uses reason:'ui-edit').
//
// startLiveBookPolling(identity) opens a background interval (the "living" behaviour: Alice's book
// self-updates when a peer's verified contact.update arrives, and Grow joiners land at the Gate).
// The app shell owns the loop so Galaxy / Grow see arrivals without sitting on Contacts.
// Returns stop() + burst(). FAIL-SOFT: a locked identity or a transient poll error never throws to
// React — the book just stays static until a later successful tick. All custody/verify/whitelist
// logic lives inside the caller; nothing here is smart about the social graph.

import {
  consumeInboundContactUpdates,
  type ConsumeDeps,
  type ContactStore,
  type KnownContact,
  type OwnerIdentity,
} from './consume-mailbox';
import { openpgpEnvelopeDecryptor } from './contact-update-envelope';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { emitContactChange } from '@/lib/contacts/contact-events';
import { emitNoteArrival } from '@/lib/notes/note-events';
import {
  loadKey,
  getContactByFingerprint,
  updateContact,
  loadIssuedCodeMap,
  isCodeOutstanding,
  codeUnderCap,
  alreadyAccepted,
  type ContactRecord,
  type IssuedCodeMap,
} from '@/lib/identity/client-store';
import type { KnownContactIdentity } from '@/lib/trust/contact-update';
import { admitContact } from '@/lib/trust/admit-contact';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import { verifyJoinerResponse, type PendingJoiner } from '@/lib/trust/joiner-response';
import { acceptJoinerAtGate } from '@/lib/trust/grow-gate';
import type { JoinerResponseSeam, NoteResponseSeam, TrustAffirmResponseSeam } from './consume-mailbox';
import { acceptInboundNote } from '@/lib/messaging/transport';
import { noteOpenpgpDecryptor } from '@/lib/messaging/seal';
import { initNotesStore, isNotesStoreUnlocked, notesStoreOwner } from '@/lib/messaging/store';
import { assertNotesStoreOpenFor } from '@/lib/messaging/notes-owner-guard';
import { acceptTrustAffirm, affirmShouldApply } from '@/lib/trust/trust-affirm-consume';
import { trustAffirmOpenpgpDecryptor } from '@/lib/trust/trust-affirm-seal';
import { edgeTrusted } from '@/lib/trust/contact-edge';

/** Steady cadence once the book is caught up. Fast enough for Gate without hammering. */
export const DEFAULT_POLL_INTERVAL_MS = 1_500;
/** After Grow mint / unlock / tab-focus — catch a joiner in ~a second, not a minute. */
export const BURST_POLL_INTERVAL_MS = 350;
export const DEFAULT_BURST_MS = 12_000;
/** Idle backoff ceiling and how many empty polls before the cadence starts doubling. */
export const MAX_IDLE_POLL_INTERVAL_MS = 15_000;
export const IDLE_TICKS_BEFORE_BACKOFF = 4;
/** Relay-visible timing is metadata (Flint #276): idle delays get ±25% random jitter, and a burst's first poll waits 0-1 s,
 *  so the relay sees "active-ish" rather than an exact focus/online timestamp. Timing depends ONLY on local UI state. */
export const IDLE_JITTER_FRACTION = 0.25;
export const BURST_START_JITTER_MS = 1000;

/**
 * Project a stored contact record into the verify seam's KnownContactIdentity.
 * Pure — the one bit of real mapping logic, unit-tested. epoch/version default to 0 (a v1 contact
 * predating the 0.14 verify bookkeeping is treated as the lowest replay floor, which is correct: the
 * first verified update it receives establishes the floor). classicalPublicKeyArmored is the armored
 * key we currently hold + trust for this contact.
 */
export function recordToKnownContact(rec: ContactRecord): KnownContactIdentity {
  return {
    fingerprint: rec.fingerprint,
    epoch: rec.epoch ?? 0,
    version: rec.version ?? 0,
    classicalPublicKeyArmored: rec.public_key,
    // pqSigningPublicKey omitted by design: the wire envelope + signature are classical (
    // the hybrid decryptor/verify path is a named upgrade, not yet on the wire). When hybrid lands, map
    // rec.pq_sig_public_key (base64) → Uint8Array here in lockstep with a hybrid decryptor swap.
  };
}

/** Build the client-store adapter the consume caller needs, bound to this owner's book. */
export function buildContactStore(ownerFingerprint: string): ContactStore {
  return {
    async lookup(contactFingerprint: string): Promise<KnownContact | null> {
      const rec = await getContactByFingerprint(ownerFingerprint, contactFingerprint);
      if (!rec) return null; // whitelist-on-fetch (I-2): not in the book → caller drops it unread, silently
      const current = rec as unknown as StoredContact; // ContactRecord ⊇ StoredContact (structural superset)
      return { known: recordToKnownContact(rec), current };
    },
    async persist(id: string, next: StoredContact): Promise<void> {
      // updateContact re-checks the fail-closed fingerprint↔key binding. A verified apply keeps the
      // fingerprint immutable and only rotates public_key to a validly-bound key, so the binding holds.
      await updateContact(id, next as Partial<ContactRecord>);
    },
  };
}

/**
 * Build the R1 return-channel seam bound to this owner + a per-poll issued-code snapshot (see
 * consume-mailbox JoinerResponseSeam). Exported for unit tests. The snapshot is loaded ONCE per poll
 * (loadIssuedCodeMap, expiry-pruned) so the accept-oracle stays SYNCHRONOUS over a stable view;
 * markAcceptedInMap mutates it in place so a same-poll duplicate joiner is dropped, and
 * recordAcceptedJoiner persists the accept across polls.
 */
export function buildJoinerSeam(owner: OwnerIdentity, codes: IssuedCodeMap): JoinerResponseSeam {
  const ownFp = owner.fingerprint;

  // The solicited-gate oracle (acceptNonce): accept iff `nonce` is one of OUR outstanding,
  // unexpired, under-cap Grow codes AND this (claimed) joiner has not already been accepted on it.
  // Receives the CLAIMED joiner fp (pre-signature) — a false claim only hurts the claimant, since the
  // crypto (Invariant-1 + signature) then requires a self-consistent, validly-signed identity.
  const acceptNonce = (nonce: string, joinerFp: string): boolean =>
    isCodeOutstanding(codes, ownFp, nonce, Date.now())
    && codeUnderCap(codes, ownFp, nonce) // per-code cap (issuer-chosen at generation; default 1)
    && !alreadyAccepted(codes, ownFp, nonce, joinerFp);

  return {
    verify: (blob: string): Promise<PendingJoiner | null> =>
      verifyJoinerResponse(
        blob,
        { fingerprint: ownFp, privateKeyArmored: owner.privateKeyArmored, passphrase: owner.passphrase, cycle: owner.cycle },
        acceptNonce,
        { requirePq: false }, // classical-era joiners accepted — the 0.4 wire is classical
      ),
    accept: async (pj: PendingJoiner): Promise<{ ignited: boolean } | null> => {
      // Gate, not Known: consume the return-channel and the issued-code slot, but do not addContact
      // until the owner admits them. Methods / Galaxy / PSI stay closed until Admit.
      return acceptJoinerAtGate(ownFp, pj, codes);
    },
  };
}

/**
 * Build the over-wire NOTE seam bound to this owner (consume-mailbox NoteResponseSeam). The mailbox is
 * shared by contact.updates + joiner-responses + over-wire notes — all the SAME openpgp envelope — so
 * WITHOUT this seam the always-on living-book poll decrypts a note via the contact-update path, fails
 * its `envelope.fingerprint` shape-check, and SILENTLY ack-DELETES it (the silent-loss). This routes a
 * note by its own type-checked decryptor to acceptInboundNote (authn-then-admit, fail-closed) → the
 * notes store. Exported for unit tests.
 */
export interface NoteSeamDeps {
  /** Owner the tab's unlocked notes store is open for (null = locked). Injectable so the guard wiring is testable. */
  openOwner: () => string | null;
  accept: typeof acceptInboundNote;
}

export function buildNoteSeam(
  owner: OwnerIdentity,
  deps: NoteSeamDeps = { openOwner: notesStoreOwner, accept: acceptInboundNote },
): NoteResponseSeam {
  const decryptNote = noteOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase, owner.cycle);
  return {
    // null for a non-note (contact.update / joiner) → consumeOne falls through to the contact path;
    // the type-check inside noteOpenpgpDecryptor is the discriminator, so this never eats a non-note.
    verify: (blob: string) => decryptNote(blob),
    accept: async (wire) => {
      // Owner guard (N10 cross-tab hardening, Flint #178309): the notes store is tab-local module state that
      // putNote writes through. If it is not open FOR THIS owner (locked, or left open for another identity),
      // refuse by THROWING → consumeOne maps it to RETRYABLE, so the note waits in the mailbox. Never omit the
      // seam instead: a missing note seam lets the blob fall through to the contact-update path and get ack-DELETED.
      assertNotesStoreOpenFor(deps.openOwner(), owner.fingerprint);
      if (owner.cycle?.ended) throw new Error('unlock cycle ended — note held for retry'); // lock landed after verify
      // acceptInboundNote: verifyNoteSender (authn — public_key↔from_fingerprint + sig) THEN admit
      // (in-book) THEN putNote; returns null on any drop (unsigned / forged / stranger — silent I-1/I-2).
      // A LOCKED notes store makes putNote throw → that propagates to the consume loop as RETRYABLE
      // (the note waits in the mailbox, never ack-deleted-unseen). buildConsumeDeps unlocks it below.
      const rec = await deps.accept({
        wire,
        isAdmitted: async (fp) => admitContact(await getContactByFingerprint(owner.fingerprint, fp)),
      });
      return rec ? { note_id: rec.note_id, thread_id: rec.thread_id, from_fingerprint: rec.from_fingerprint } : null;
    },
  };
}

/**
 * Build the MUTUAL-TRUST AFFIRMATION seam bound to this owner (consume-mailbox TrustAffirmResponseSeam).
 * The mailbox is shared by contact.updates + joiner-responses + notes + affirmations — all the SAME
 * openpgp envelope — so WITHOUT this seam the always-on poll decrypts an affirmation via the contact-
 * update path, fails its `envelope.fingerprint` shape-check, and SILENTLY ack-DELETES it (the silent-
 * loss). This routes an affirmation by its own type-checked decryptor to acceptTrustAffirm (authn →
 * bind-to-me → admit → apply), persisting the flip into the CLIENT ContactRecord.mutual — the field
 * livingEdgeStatus reads to phase an edge mutual. Exported for unit tests.
 *
 * APPLY TARGET (grounded ☀8180 — corrects the handoff's "updateMutualState" plan): the Node-fs
 * TrustGraphManager.updateMutualState has ZERO client callers and writes a file the browser never
 * reads — wiring to it would be a VISUAL NO-OP. The field the UI actually reads is
 * ContactRecord.mutual (contactRecordToEdge → livingEdgeStatus), persisted here via updateContact.
 * reciprocal = (I independently trust them, per the shared edgeTrusted predicate) && trusts — reading
 * the EXISTING trusted state, which a remote wire can never promote (updateContact pt5 gate). So an
 * in-book affirm sets they_trust_me (inbound) but mutual requires MY own prior owner-verified trust.
 */
export function buildTrustAffirmSeam(owner: OwnerIdentity): TrustAffirmResponseSeam {
  const decryptAffirm = trustAffirmOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase, owner.cycle);
  return {
    // null for a non-affirmation (contact.update / joiner / note) → consumeOne falls through; the
    // type-check inside trustAffirmOpenpgpDecryptor is the discriminator, so this never eats a non-affirm.
    verify: (blob) => decryptAffirm(blob),
    accept: (wire) =>
      acceptTrustAffirm({
        wire,
        ownerFingerprint: owner.fingerprint,
        // whitelist-on-fetch admit (I-2, the FALSE-MUTUAL gate): flip ONLY for an in-book sender.
        isAdmitted: async (fp) => admitContact(await getContactByFingerprint(owner.fingerprint, fp)),
        // apply sink — persist the flip into the CLIENT store. A LOCKED store makes updateContact throw
        // → propagates as RETRYABLE (the affirmation waits in the mailbox, never ack-deleted-unseen).
        applyMutual: async (fromFp, trusts, sentAt) => {
          const rec = await getContactByFingerprint(owner.fingerprint, fromFp);
          if (!rec) {
            // Admitted a moment ago but gone now (removed mid-poll) — nothing to flip. Idempotent no-op;
            // report reciprocal:false and let the ack clean up (the edge no longer exists to show mutual).
            throw new Error('trust-affirm applyMutual: contact vanished between admit and apply');
          }
          // PER-SENDER MONOTONICITY (#3 anti-rollback, Flint #169539 + NaN/future hardening #169647): apply
          // only if the sender's SIGNED sent_at is a plausible timestamp AND not strictly older than the
          // last applied for this sender — a stale/replayed/back-dated "I trust you" must never overwrite a
          // newer "I broke trust" (false-Mutual revival), and a garbage/future ts must not defeat or poison
          // the ordering. The cursor (last_affirm_at) lives INSIDE `mutual`, so it advances in the SAME
          // updateContact tx as they_trust_me (crash-safe). `null` ⇒ terminal drop.
          const prevAffirmAt = (rec.mutual as { last_affirm_at?: string } | undefined)?.last_affirm_at;
          if (!affirmShouldApply(sentAt, prevAffirmAt, Date.now())) return null;
          const iTrustThem = edgeTrusted(rec);
          const mutual = {
            they_trust_me: trusts,
            last_sync: new Date().toISOString(),
            reciprocal: iTrustThem && trusts,
            last_affirm_at: sentAt,
          };
          await updateContact(rec.id, { mutual } as Partial<ContactRecord>);
          return { id: rec.id, reciprocal: mutual.reciprocal };
        },
      }),
  };
}

/** Assemble the consume deps from an unlocked identity, or null if it's locked / has no armored key. */
export async function buildConsumeDeps(
  identity: unknown,
  opts: { fetchImpl?: typeof fetch } = {},
): Promise<ConsumeDeps | null> {
  const id = identity as {
    identity?: { fingerprint?: string; public_key?: string };
    post_quantum?: { kem_public_key?: string; sig_public_key?: string };
  } | null;
  const fingerprint = id?.identity?.fingerprint;
  const publicKeyArmored = id?.identity?.public_key;
  if (!fingerprint || !publicKeyArmored) return null;
  const key = await loadKey(fingerprint); // null while the session is locked (keys encrypted at rest)
  if (!key) return null;
  const owner: OwnerIdentity = {
    fingerprint,
    publicKeyArmored,
    privateKeyArmored: key.privateKey,
    passphrase: key.passphrase,
    // One unlock for this poll cycle (decryptors + poll/ack signing). The caller drops it when the cycle ends.
    cycle: makeUnlockCycle(key.privateKey, key.passphrase),
    // §5 canonical-id: thread the identity's PQ pubkeys so the owner-auth bundle lets the relay
    // recompute the 64-hex canonical fp. IdentityData.post_quantum is top-level (browser-identity.ts).
    // Absent (classical identity) → verify falls back to the 40-hex OpenPGP path.
    kemPublicKey: id?.post_quantum?.kem_public_key,
    sigPublicKey: id?.post_quantum?.sig_public_key,
  };
  // R1 return-channel: load the issued-code snapshot ONCE per poll (this fn is called per poll cycle by
  // both pollLiveBookOnce and startLiveBookPolling.tick) so the joiner accept-oracle is sync + reflects
  // codes minted since the last poll. loadIssuedCodeMap prunes expired entries.
  const codes: IssuedCodeMap = await loadIssuedCodeMap();
  // Unlock the notes store so received over-wire notes PERSIST on arrival (not just once /msg is open).
  // Same unlock passphrase the vault uses (store.ts initNotesStore, separate salt); the poll only runs
  // for an UNLOCKED identity, so the credential is already in memory — no new trust boundary crossed.
  // Guarded (idempotent) + fail-soft: if it can't unlock, the note seam's putNote throws → the note is
  // held as retryable in the mailbox (never ack-deleted-unseen), so there is still no silent-loss.
  // Only init when LOCKED. If it is already open for a DIFFERENT owner we must not init over it (openDb caches the
  // previous identity's handle); note accept() refuses in that state (see buildNoteSeam), so notes are held, not lost.
  if (!isNotesStoreUnlocked()) {
    try {
      await initNotesStore(key.passphrase, fingerprint); // owner-scope: per-identity notes DB (P1#1)
    } catch {
      /* notes store unavailable → notes are held (retryable), delivered when it unlocks. No loss. */
    }
  }
  return {
    owner,
    decrypt: openpgpEnvelopeDecryptor(key.privateKey, key.passphrase, owner.cycle),
    store: buildContactStore(fingerprint),
    joiner: buildJoinerSeam(owner, codes),
    note: buildNoteSeam(owner),
    affirm: buildTrustAffirmSeam(owner),
    emit: (e) => emitContactChange({ ids: [e.id], reason: 'live-apply' }),
    // Over-wire note persisted on the shared poll → fan the inbox-repaint to the Notes tab
    // (NotesInbox subscribes to subscribeNoteArrivals). Mirrors emit: for contacts. (Athena — live-repaint wire.)
    emitNote: (e) => emitNoteArrival(e),
    // Mutual-trust flip persisted on the shared poll → repaint the contact row / trust map via the SAME
    // contact beat (reason:'live-apply') so the edge re-reads ContactRecord.mutual → phases to Mutual
    // (or inbound). Reuses the existing bus; no new emitter. (Athena — if a dedicated trust beat is wanted.)
    emitTrust: (e) => emitContactChange({ ids: [e.id], reason: 'live-apply' }),
    fetchImpl: opts.fetchImpl,
  };
}

export interface LiveBookPollHandle {
  stop: () => void;
  /** Temporarily poll at BURST_POLL_INTERVAL_MS, then settle back. Immediate tick. */
  burst: (durationMs?: number) => void;
}

/**
 * Start polling the owner's return-channel mailbox on an interval. Each tick consumes any pending
 * verified contact.updates; on a successful apply the caller emits reason:'live-apply' → the open book
 * repaints the row data-live="push". Returns a handle whose stop() clears the interval.
 *
 * Fail-soft + non-overlapping: a locked identity or a transient error is swallowed (logged locally, never
 * echoed — I-1) so one bad tick can neither throw to React nor wedge the loop; the next tick retries.
 * The first tick fires immediately so a freshly-opened book catches already-waiting mail without waiting
 * a full interval.
 */
/**
 * Poll delay policy (pure). Steady cadence doubles after IDLE_TICKS_BEFORE_BACKOFF consecutive empty polls,
 * capped at maxIdleMs. Burst (Grow mint / unlock / tab focus) and any non-empty poll snap back to full speed.
 */
export function nextPollDelayMs(a: { idleTicks: number; bursting: boolean; intervalMs: number; maxIdleMs: number }): number {
  if (a.bursting) return BURST_POLL_INTERVAL_MS;
  const over = a.idleTicks - IDLE_TICKS_BEFORE_BACKOFF;
  return over <= 0 ? a.intervalMs : Math.min(a.maxIdleMs, a.intervalMs * 2 ** Math.min(over, 10));
}

/** base ± IDLE_JITTER_FRACTION, uniformly. `random` is injectable for tests (default Math.random). Never keyed on content. */
export function jitterDelayMs(baseMs: number, random: () => number = Math.random): number {
  return Math.round(baseMs * (1 + (random() * 2 - 1) * IDLE_JITTER_FRACTION));
}

/** 0..BURST_START_JITTER_MS random wait before a burst's first poll. */
export function burstStartDelayMs(random: () => number = Math.random): number {
  return Math.floor(random() * BURST_START_JITTER_MS);
}

/**
 * One consume tick — used by Galaxy pull-to-refresh. Fail-soft: locked / no
 * identity is a no-op (the book is still re-read by the caller). Does not invent
 * a living wire; it only consumes what the mailbox already has.
 */
export async function pollLiveBookOnce(
  identity: unknown,
  opts: { fetchImpl?: typeof fetch } = {},
): Promise<void> {
  const deps = await buildConsumeDeps(identity, { fetchImpl: opts.fetchImpl });
  if (!deps) return;
  try {
    await consumeInboundContactUpdates(deps);
  } finally {
    deps.owner.cycle?.drop();
  }
}

export function startLiveBookPolling(
  identity: unknown,
  opts: { intervalMs?: number; maxIdleIntervalMs?: number; fetchImpl?: typeof fetch; random?: () => number } = {},
): LiveBookPollHandle {
  const intervalMs = opts.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const maxIdleMs = opts.maxIdleIntervalMs ?? MAX_IDLE_POLL_INTERVAL_MS;
  const random = opts.random ?? Math.random;
  let stopped = false;
  let inFlight = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let burstTimer: ReturnType<typeof setTimeout> | null = null;
  let bursting = false;
  let idleTicks = 0; // consecutive ticks that found nothing; reset by any activity or burst

  // Burst cadence stays exact; every idle delay is jittered (see IDLE_JITTER_FRACTION).
  const nextDelay = () => {
    const base = nextPollDelayMs({ idleTicks, bursting, intervalMs, maxIdleMs });
    return bursting ? base : jitterDelayMs(base, random);
  };

  const schedule = () => {
    if (timer) clearTimeout(timer);
    timer = null;
    if (stopped) return;
    timer = setTimeout(() => void tick(), nextDelay());
  };

  const tick = async () => {
    if (stopped || inFlight) return; // never overlap polls
    inFlight = true;
    let active = false;
    try {
      const deps = await buildConsumeDeps(identity, { fetchImpl: opts.fetchImpl });
      if (!deps) return; // locked / no identity — stay static, retry next tick
      try {
        const s = await consumeInboundContactUpdates(deps);
        active = s.polled > 0;
      } finally {
        deps.owner.cycle?.drop(); // cycle ends with the tick; never outlives it
      }
    } catch (err) {
      // local-only diagnostic; never surfaced to the peer/relay (I-1). One bad tick must not wedge the loop.
      console.error('[live-book-poll] poll tick failed (will retry):', err);
    } finally {
      inFlight = false;
      idleTicks = active ? 0 : idleTicks + 1;
      schedule();
    }
  };

  const burst = (durationMs = DEFAULT_BURST_MS) => {
    if (stopped) return;
    idleTicks = 0;
    bursting = true;
    if (burstTimer) clearTimeout(burstTimer);
    burstTimer = setTimeout(() => {
      burstTimer = null;
      bursting = false;
      idleTicks = 0;
    }, durationMs);
    // First poll after a wake waits 0-1 s (not an exact focus timestamp). If a tick is already in flight, its
    // finally{} reschedules at burst speed instead.
    if (!inFlight) {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => void tick(), burstStartDelayMs(random));
    }
  };

  void tick(); // immediate first poll; each tick reschedules itself

  return {
    stop: () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
      if (burstTimer) clearTimeout(burstTimer);
      burstTimer = null;
    },
    burst,
  };
}
