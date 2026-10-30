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
import type { JoinerResponseSeam, NoteResponseSeam, ReceiptResponseSeam } from './consume-mailbox';
import { acceptInboundNote } from '@/lib/messaging/transport';
import { noteOpenpgpDecryptor, parseNoteWire, receiptOpenpgpDecryptor, parseReceiptWire } from '@/lib/messaging/seal';
import { initNotesStore, isNotesStoreUnlocked, notesStoreOwner, getNote, putNote } from '@/lib/messaging/store';
import { assertNotesStoreOpenFor } from '@/lib/messaging/notes-owner-guard';
import type { NoteWireV0 } from '@/lib/messaging/types';
import { verifyReceiptWire } from '@/lib/crypto/delivery-receipt';
import { canonicalPubsFromArmoredPublicKey } from '@/lib/identity/fingerprint';

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
  // Optional recipient-emit (Athena — Nov-5 delivered-receipt): after a note is accepted, send a
  // cryptographically-signed receipt back to its sender so their "Sent · unconfirmed." graduates to
  // "Delivered". Best-effort by contract — the caller's closure must never throw (a receipt is a bonus
  // on top of the already-persisted note; a failed emit must not fail note acceptance). Omitted by unit
  // tests / legacy callers → exact prior behaviour (no receipt sent).
  sendReceipt?: (wire: NoteWireV0) => Promise<void>,
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
        openRatchet: async (fromFp, body) => {
          const { loadOwnerRatchetIdentity, loadPeerRatchet } = await import('@/lib/messaging/ratchet-keys');
          const { openDirectNoteStaged, ownerBoundRatchetIO } = await import('@/lib/messaging/direct-session');
          const self = await loadOwnerRatchetIdentity(owner.fingerprint, {
            identity: { fingerprint: owner.fingerprint, public_key: owner.publicKeyArmored },
            post_quantum: { kem_public_key: owner.kemPublicKey, sig_public_key: owner.sigPublicKey },
          });
          const peer = await loadPeerRatchet(owner.fingerprint, fromFp);
          if (!self || !peer) return null;
          // R4 + R2: open WITHOUT persisting (acceptInboundNote commits after the note is stored), against the session store bound to THIS owner.
          return openDirectNoteStaged(fromFp, body, self, peer, ownerBoundRatchetIO(owner.fingerprint));
        },
      });
      if (!rec) return null; // dropped (unsigned / forged / stranger) — no receipt for a note we didn't accept
      // Best-effort delivery receipt back to the sender. The wire was AUTHENTICATED by acceptInboundNote
      // (verifyNoteSender bound public_key↔from_fingerprint), so wire.public_key + wire.from_fingerprint
      // are trustworthy to seal+address a receipt to. Fail-closed on error: never let a receipt-emit
      // failure undo the note we already persisted.
      if (sendReceipt) {
        try {
          await sendReceipt(wire);
        } catch (err) {
          console.error('[live-book-poll] delivery-receipt emit failed (note still delivered locally):', err);
        }
      }
      return { note_id: rec.note_id, thread_id: rec.thread_id, from_fingerprint: rec.from_fingerprint };
    },
  };
}

/**
 * Build the DELIVERY-RECEIPT seam bound to this owner (consume-mailbox ReceiptResponseSeam) — the SENDER
 * side. When the owner polls their own mailbox and finds a receipt sealed to them, this recovers the
 * OUTBOUND note it confirms and verifies the delivering recipient's signature, then marks the note
 * delivered. Exported for unit tests.
 *
 * ★ THE HONESTY INVARIANT (Flint carry-forward): `delivered: true` is written on EXACTLY ONE LINE — the
 * putNote below, reached ONLY after verifyReceiptWire returns true. Every other path (unknown note,
 * recipient not in book, classical contact with no PQ sig key, forged/garbled receipt, nonce mismatch)
 * returns null → the note keeps the honest 'Sent · unconfirmed.' floor. A false "Delivered" is
 * UNREACHABLE by construction.
 */
/**
 * The I/O the receipt ACCEPT performs: OUR stored outbound note (source of truth for the expected note_id / nonce / recipient),
 * the recipient's card in OUR book (the ONLY source of the keys a receipt is checked against), and the one write.
 * Injectable so the verify-then-mark-delivered path can be tested with REAL crypto and no IndexedDB (same pattern as
 * {@link NoteSeamDeps}). Defaults are the real stores. The accept body is 620cd7b's, with exactly these three calls routed
 * through `deps` and nothing else changed.
 */
export interface ReceiptSeamDeps {
  getNote: typeof getNote;
  putNote: typeof putNote;
  getContactByFingerprint: typeof getContactByFingerprint;
}

export function buildReceiptSeam(
  owner: OwnerIdentity,
  hybrid?: HybridSecretsSource,
  deps: ReceiptSeamDeps = { getNote, putNote, getContactByFingerprint },
): ReceiptResponseSeam {
  // Single dual-read chokepoint, same discipline as the note seam: hybrid-FIRST + classical FALLBACK (off the N10 unlock
  // cycle). parseReceiptWire is the type-gate on BOTH legs → no-cross-swallow is byte-identical.
  const classicalReceipt = receiptOpenpgpDecryptor(owner.privateKeyArmored, owner.passphrase, owner.cycle);
  const verifyReceipt = hybrid
    ? dualReadOpener(
        makeHybridOpener(openHybridForCycle(owner, hybrid), parseReceiptWire),
        classicalReceipt,
      )
    : classicalReceipt;
  return {
    // null for a non-receipt (contact.update / joiner / note) → consumeOne falls through; parseReceiptWire
    // is the discriminator (both legs), so this never eats a non-receipt.
    verify: (blob) => verifyReceipt(blob),
    accept: async (wire) => {
      // Recover OUR stored outbound note — the source-of-truth for the expected (note_id, nonce, recipient).
      const note = await deps.getNote(wire.note_id);
      if (!note || note.direction !== 'outbound' || !note.receipt_nonce) return null; // unknown/ineligible → drop
      const peerFp = note.to_fingerprints[0];
      if (!peerFp) return null;
      // The delivering recipient's pubkeys come from THEIR card in our book (we sent them a note → admitted).
      const card = await deps.getContactByFingerprint(owner.fingerprint, peerFp);
      if (!card) return null; // recipient no longer in book → can't verify → fail-safe drop (floor holds)
      const rec = card as {
        public_key?: string; peer_public_key?: string;
        pq_kem_public_key?: string; peer_pq_kem_public_key?: string;
        pq_sig_public_key?: string; peer_pq_sig_public_key?: string;
      };
      const armored = String(rec.public_key || rec.peer_public_key || '');
      const kemB64 = rec.pq_kem_public_key || rec.peer_pq_kem_public_key;
      const sigB64 = rec.pq_sig_public_key || rec.peer_pq_sig_public_key;
      if (!armored || !kemB64 || !sigB64) return null; // classical (no-PQ) contact → no sig key → fail-safe drop
      let pubs;
      try {
        pubs = await canonicalPubsFromArmoredPublicKey(armored, kemB64, sigB64);
      } catch {
        return null; // malformed card keys → can't verify → fail-safe drop
      }
      const ok = verifyReceiptWire(
        wire,
        { noteId: note.note_id, nonce: note.receipt_nonce, recipientFingerprint: peerFp },
        pubs.signPub,
        pubs.sigPub,
      );
      if (!ok) return null; // forged / garbled / mismatched → floor 'Sent · unconfirmed.' holds, NO false Delivered
      // ★ THE ONE LINE: a VERIFIED receipt → mark the note delivered. Idempotent on redelivery (putNote by id).
      await deps.putNote({ ...note, delivered: true });
      return { note_id: note.note_id, thread_id: note.thread_id, from_fingerprint: peerFp };
    },
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
  // `lazy` is declared below because it needs the cycle; the getter only runs at drop time, after it exists.
  const cycle = cycleDroppingHybrid(makeUnlockCycle(key.privateKey, key.passphrase), () => lazy.current());
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
  const lazy = lazyCycleHybrid(cycle, owner.kemPublicKey, async () => {
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
  // NO recipient-emit of delivery receipts (Archie #1823 option (a), A5-d / S62 v4 C8): the S06 v1 receipt
  // is identity-signed, i.e. a transferable proof that we received a note, so it never ships. The sender-side
  // verify (buildReceiptSeam) stays; "Delivered" lights up once S62's designated-verifier MAC receipt lands.
  // Pinned by receipt-emit-unwired.test.ts.

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
    receipt: buildReceiptSeam(owner, hybrid),
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
    // Delivery receipt verified on the shared poll → an OUTBOUND note is now 'Delivered'. Reuse the note-
    // arrival bus so the open thread re-reads + repaints the status (no new emitter). (Athena — delivered-repaint.)
    emitReceipt: (e) => emitNoteArrival(e),
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
