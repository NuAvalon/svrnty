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
import { openpgpEnvelopeDecryptor, parseContactUpdateWire } from './contact-update-envelope';
import { makeUnlockCycle, type UnlockCycle } from '@/lib/crypto/unlock-cycle';
import { emitContactChange } from '@/lib/contacts/contact-events';
import { emitNoteArrival } from '@/lib/notes/note-events';
import {
  loadKey,
  loadPQKeys,
  getContactByFingerprint,
  updateContact,
  loadIssuedCodeMap,
  isCodeOutstanding,
  codeUnderCap,
  alreadyAccepted,
  type ContactRecord,
  type IssuedCodeMap,
} from '@/lib/identity/client-store';
import { resolveHybrid, type HybridSecretsSource, type LivingBookHybridSecrets } from '@/lib/crypto/living-book-sleeve';
import { deriveOwnerHybridSecretsFromKey } from '@/lib/crypto/living-book-receive';
// L7 single dual-read chokepoint (Option-B): the 3 openers are classical-only; the hybrid leg + fallback
// compose HERE, once per seam, off the owner's derived mailbox secrets (openMailboxEnvelope).
import { makeHybridOpener, dualReadOpener, type EnvelopeOpener } from '@/lib/sync/hybrid-dual-read';
import { openMailboxEnvelope } from '@/lib/crypto/mailbox-envelope';
import type { KnownContactIdentity } from '@/lib/trust/contact-update';
import { admitContact } from '@/lib/trust/admit-contact';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import { verifyJoinerResponse, type PendingJoiner } from '@/lib/trust/joiner-response';
import { acceptJoinerAtGate } from '@/lib/trust/grow-gate';
import type { JoinerResponseSeam, NoteResponseSeam, TrustAffirmResponseSeam } from './consume-mailbox';
import { acceptInboundNote } from '@/lib/messaging/transport';
import { noteOpenpgpDecryptor, parseNoteWire } from '@/lib/messaging/seal';
import { initNotesStore, isNotesStoreUnlocked, notesStoreOwner } from '@/lib/messaging/store';
import { assertNotesStoreOpenFor } from '@/lib/messaging/notes-owner-guard';
import { acceptTrustAffirm, affirmShouldApply } from '@/lib/trust/trust-affirm-consume';
import { trustAffirmOpenpgpDecryptor, parseTrustAffirmWire } from '@/lib/trust/trust-affirm-seal';
import { edgeTrusted } from '@/lib/trust/contact-edge';

/** Steady cadence once the book is caught up. Fast enough for Gate without hammering. */
export const DEFAULT_POLL_INTERVAL_MS = 1_500;
/** After Grow mint / unlock / tab-focus — catch a joiner in ~a second, not a minute. */
export const BURST_POLL_INTERVAL_MS = 350;
export const DEFAULT_BURST_MS = 12_000;

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
export function buildJoinerSeam(owner: OwnerIdentity, codes: IssuedCodeMap, hybrid?: HybridSecretsSource): JoinerResponseSeam {
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
        // DUAL-READ: hybrid secrets (when present) let verify open a PQ-hybrid joiner-response FIRST, else
        // it falls through to the classical OpenPGP decrypt — same giver identity either way.
        { fingerprint: ownFp, privateKeyArmored: owner.privateKeyArmored, passphrase: owner.passphrase, hybrid, cycle: owner.cycle },
        acceptNonce,
        { requirePq: false }, // classical-era joiners still accepted — the signature suite is separate from the envelope
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
  hybrid?: HybridSecretsSource,
): NoteResponseSeam {
  // Single dual-read chokepoint: hybrid-FIRST (makeHybridOpener → openMailboxEnvelope + parseNoteWire),
  // classical FALLBACK (noteOpenpgpDecryptor, off the N10 unlock cycle). parseNoteWire is the type-gate on BOTH legs → no-cross-swallow.
  const classicalNote = noteOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase, owner.cycle);
  const verifyNote = hybrid
    ? dualReadOpener(
        makeHybridOpener(openHybridForCycle(owner, hybrid), parseNoteWire),
        classicalNote,
      )
    : classicalNote;
  return {
    // null for a non-note (contact.update / joiner) → consumeOne falls through to the contact path;
    // parseNoteWire is the discriminator (both legs), so this never eats a non-note.
    verify: (blob: string) => verifyNote(blob),
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
export function buildTrustAffirmSeam(owner: OwnerIdentity, hybrid?: HybridSecretsSource): TrustAffirmResponseSeam {
  // Single dual-read chokepoint: hybrid-FIRST + classical FALLBACK (off the N10 unlock cycle), reusing parseTrustAffirmWire (the same
  // asAffirm type-gate on BOTH legs → no-cross-swallow).
  const classicalAffirm = trustAffirmOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase, owner.cycle);
  const verifyAffirm = hybrid
    ? dualReadOpener(
        makeHybridOpener(openHybridForCycle(owner, hybrid), parseTrustAffirmWire),
        classicalAffirm,
      )
    : classicalAffirm;
  return {
    // null for a non-affirmation (contact.update / joiner / note) → consumeOne falls through; parseTrustAffirmWire
    // is the discriminator (both legs), so this never eats a non-affirm.
    verify: (blob) => verifyAffirm(blob),
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

// deriveOwnerHybridSecrets moved to @/lib/crypto/living-book-receive (shared by the FE + headless consume
// deps so the one dual-read chokepoint derives owner open-material the same way on both paths).

/**
 * The hybrid leg's envelope opener, bound to the poll cycle (S14 on N10; Flint #179187). A lock/switch mid-tick
 * must stop the hybrid leg exactly like the classical one. A dead cycle opens NOTHING: null falls through to the
 * classical leg, which also refuses, so the consume loop sees a dead cycle and leaves the envelope retryable
 * (never acked). `hybrid` may be a lazy provider (see lazyCycleHybrid); it is resolved only when a hybrid-shaped
 * package actually reaches this opener, and the cycle is re-checked after it resolves.
 */
export function openHybridForCycle(owner: { cycle?: UnlockCycle }, hybrid: HybridSecretsSource): EnvelopeOpener {
  return async (pkg) => {
    if (owner.cycle?.ended) return null;
    const h = await resolveHybrid(hybrid);
    if (!h || owner.cycle?.ended) return null; // no derivable secret, or a lock landed while deriving
    return openMailboxEnvelope(pkg, h.secrets, h.myFp);
  };
}

export interface LazyCycleHybrid {
  /** Memoized for the cycle. Derives on the FIRST call from the cycle's already-unlocked key (no second unlock). */
  source: () => Promise<LivingBookHybridSecrets | undefined>;
  /** What has been derived so far (for zeroing at cycle end); undefined before the first hybrid blob arrives. */
  current: () => LivingBookHybridSecrets | undefined;
}

/**
 * Flint R1/R2 (#275): derive the owner's hybrid open-material LAZILY and from the poll cycle's single unlock.
 *  • classical identity or empty/classical mailbox → nothing is derived, no key is touched (zero cost);
 *  • the first hybrid-shaped blob derives once, reusing cycle.key() (the unlock the classical decryptors share);
 *  • nothing is derived before then, so an error between "cycle created" and "deps returned" finds no derived secret;
 *  • if the cycle ended while deriving, the freshly derived bytes are zeroed immediately and never returned.
 * Zeroing at cycle end is cycleDroppingHybrid(base, current). Fail-soft: any read error → undefined (classical).
 */
export function lazyCycleHybrid(
  cycle: UnlockCycle,
  kemPublicKey: string | undefined,
  loadKemSecret: () => Promise<string | undefined>,
  derive: typeof deriveOwnerHybridSecretsFromKey = deriveOwnerHybridSecretsFromKey, // injectable for tests
): LazyCycleHybrid {
  let pending: Promise<LivingBookHybridSecrets | undefined> | null = null;
  let derived: LivingBookHybridSecrets | undefined;
  return {
    source() {
      if (!kemPublicKey || cycle.ended) return Promise.resolve(undefined);
      if (!pending) {
        pending = (async () => {
          try {
            const kemSecretB64 = await loadKemSecret();
            if (!kemSecretB64) return undefined;
            const key = await cycle.key(); // throws if the cycle ended; caught below
            const h = await derive(key, kemPublicKey, kemSecretB64);
            if (!h) return undefined;
            if (cycle.ended) {
              h.secrets.x25519Sec.fill(0);
              h.secrets.mlkem1024Sec.fill(0);
              return undefined;
            }
            derived = h;
            return h;
          } catch {
            return undefined; // never block the poll on a PQ-key read
          }
        })();
      }
      return pending;
    },
    current: () => derived,
  };
}

/** Run `build`; if it throws, end the cycle (drops the unlocked-key reference + zeroes anything derived) and rethrow. */
export async function dropCycleOnThrow<T>(cycle: UnlockCycle, build: () => Promise<T>): Promise<T> {
  try {
    return await build();
  } catch (e) {
    cycle.drop();
    throw e;
  }
}

/**
 * Wrap the poll's unlock cycle so dropping it (the callers' `finally`) also zeroes the derived hybrid secret BYTES:
 * the derived secret bytes have tick lifetime. Not claimed: the passphrase and the ML-KEM secret's base64 STRING are
 * JS strings and cannot be zeroed. `getHybrid` is read at drop time because the secrets are derived lazily.
 */
export function cycleDroppingHybrid(base: UnlockCycle, getHybrid: () => LivingBookHybridSecrets | undefined): UnlockCycle {
  return {
    get ended() {
      return base.ended;
    },
    key: () => base.key(),
    drop() {
      base.drop();
      const h = getHybrid();
      if (h) {
        h.secrets.x25519Sec.fill(0);
        h.secrets.mlkem1024Sec.fill(0);
      }
    },
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
  let lazy: LazyCycleHybrid | undefined; // created once the cycle exists; its derived bytes are zeroed with the cycle
  const cycle = cycleDroppingHybrid(makeUnlockCycle(key.privateKey, key.passphrase), () => lazy?.current());
  const owner: OwnerIdentity = {
    fingerprint,
    publicKeyArmored,
    privateKeyArmored: key.privateKey,
    passphrase: key.passphrase,
    // One unlock for this poll cycle (decryptors + poll/ack signing). The caller drops it when the cycle ends.
    cycle,
    // §5 canonical-id: thread the identity's PQ pubkeys so the owner-auth bundle lets the relay
    // recompute the 64-hex canonical fp. IdentityData.post_quantum is top-level (browser-identity.ts).
    // Absent (classical identity) → verify falls back to the 40-hex OpenPGP path.
    kemPublicKey: id?.post_quantum?.kem_public_key,
    sigPublicKey: id?.post_quantum?.sig_public_key,
  };
  // HNDL dual-read: this owner's mailbox open-material lets the openers open a PQ-hybrid deposit FIRST, falling
  // back to classical for legacy blobs. DERIVED LAZILY (Flint R1/R2 on #275): nothing is read or unlocked until a
  // hybrid-shaped blob arrives, and then from the cycle's ONE unlock (no second decryptKey). Fail-soft: a classical
  // identity / PQ-read error → no secret → classical openers. ML-KEM secret = vault PQ bundle (loadPQKeys); the
  // enc (x25519) secret = the cycle's unlocked identity key.
  lazy = lazyCycleHybrid(cycle, owner.kemPublicKey, async () => {
    const pq = await loadPQKeys(fingerprint);
    return pq?.pq_kem_secret_key ?? pq?.kem?.secretKey;
  });
  const hybrid = lazy.source;


  // R1 return-channel: load the issued-code snapshot ONCE per poll (this fn is called per poll cycle by
  // both pollLiveBookOnce and startLiveBookPolling.tick) so the joiner accept-oracle is sync + reflects
  // codes minted since the last poll. loadIssuedCodeMap prunes expired entries.
  // If this throws, the poll never receives deps and so never runs its cycle.drop(): end the cycle here (R1).
  const codes: IssuedCodeMap = await dropCycleOnThrow(cycle, () => loadIssuedCodeMap());
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
  // contact-update (the consume catch-all): single dual-read chokepoint — hybrid-first + classical fallback.
  const classicalCU = openpgpEnvelopeDecryptor(key.privateKey, key.passphrase, owner.cycle);
  return {
    owner,
    decrypt: hybrid
      ? dualReadOpener(
          makeHybridOpener(openHybridForCycle(owner, hybrid), parseContactUpdateWire),
          classicalCU,
        )
      : classicalCU,
    store: buildContactStore(fingerprint),
    joiner: buildJoinerSeam(owner, codes, hybrid),
    note: buildNoteSeam(owner, undefined, hybrid),
    affirm: buildTrustAffirmSeam(owner, hybrid),
    // ③ loud-not-silent (Flint #168225): a hybrid blob is never acked unopened. advertise-kem-pub but
    // the ML-KEM secret did NOT derive (loadPQKeys failed / transiently locked) ⇒ a hybrid blob is LEFT FOR
    // RETRY by consumeOne, never silently acked+dropped. Keyed on ACTUAL derivability (re-evaluated every
    // poll off loadPQKeys) — a derivable owner is FALSE → opens; never retryable-forever (Flint #168382).
    // Lazy: evaluated only when a hybrid-shaped blob arrives (consumeOne), off the same memoized derivation.
    hybridSecretMissing: async () => !!owner.kemPublicKey && !(await hybrid()),
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
  opts: { intervalMs?: number; fetchImpl?: typeof fetch } = {},
): LiveBookPollHandle {
  const intervalMs = opts.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  let stopped = false;
  let inFlight = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  let burstTimer: ReturnType<typeof setTimeout> | null = null;

  const tick = async () => {
    if (stopped || inFlight) return; // never overlap polls
    inFlight = true;
    try {
      const deps = await buildConsumeDeps(identity, { fetchImpl: opts.fetchImpl });
      if (!deps) return; // locked / no identity — stay static, retry next tick
      try {
        await consumeInboundContactUpdates(deps);
      } finally {
        deps.owner.cycle?.drop();
      }
    } catch (err) {
      // local-only diagnostic; never surfaced to the peer/relay (I-1). One bad tick must not wedge the loop.
      console.error('[live-book-poll] poll tick failed (will retry):', err);
    } finally {
      inFlight = false;
    }
  };

  const setCadence = (ms: number) => {
    if (timer) clearInterval(timer);
    if (stopped) return;
    timer = setInterval(() => void tick(), ms);
  };

  const burst = (durationMs = DEFAULT_BURST_MS) => {
    if (stopped) return;
    void tick();
    setCadence(BURST_POLL_INTERVAL_MS);
    if (burstTimer) clearTimeout(burstTimer);
    burstTimer = setTimeout(() => {
      burstTimer = null;
      if (!stopped) setCadence(intervalMs);
    }, durationMs);
  };

  void tick(); // immediate first poll
  setCadence(intervalMs);

  return {
    stop: () => {
      stopped = true;
      if (timer) clearInterval(timer);
      timer = null;
      if (burstTimer) clearTimeout(burstTimer);
      burstTimer = null;
    },
    burst,
  };
}
