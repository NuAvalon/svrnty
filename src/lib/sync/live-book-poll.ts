// src/lib/sync/live-book-poll.ts
// The RUNTIME poll call-site for the living address book (demo-spine beat-4 — Athena).
//
// consumeInboundContactUpdates (PR#33) is deliberately seam-injected so it stays IndexedDB-free and
// crypto-agnostic. This module is the one place those seams are bound to the real client runtime, and
// the poll loop that actually drives them:
//   • owner   — the unlocked local identity: fingerprint + armored public key (from `identity`) + the
//               private key + passphrase (from loadKey; null while the session is locked).
//   • decrypt — openpgpEnvelopeDecryptor bound to the owner's private key (the classical envelope;
//               the hybrid-PQ decryptor is a named upgrade that swaps here with zero caller change,
//               Flint #116410).
//   • store   — a client-store adapter: getContactByFingerprint → {known, current}; updateContact = persist.
//   • emit    — Apollo's live-beat seam: after a verified apply, emitContactChange({ids:[id],reason:'live-apply'})
//               so ContactManagement repaints the row data-live="push" — the honest beat-4 signal, which
//               can ONLY fire on an incoming apply (a local ui-edit uses reason:'ui-edit').
//
// startLiveBookPolling(identity) opens a background interval (the "living" behaviour: Alice's book
// self-updates when a peer's verified contact.update arrives) and returns stop(). It is FAIL-SOFT: a
// locked identity or a transient poll error never throws to React — the book just stays static until a
// later successful tick. All custody/verify/whitelist logic lives inside the caller; nothing here is
// smart about the social graph.

import {
  consumeInboundContactUpdates,
  type ConsumeDeps,
  type ContactStore,
  type KnownContact,
  type OwnerIdentity,
} from './consume-mailbox';
import { openpgpEnvelopeDecryptor } from './contact-update-envelope';
import { emitContactChange } from '@/lib/contacts/contact-events';
import {
  loadKey,
  getContactByFingerprint,
  updateContact,
  type ContactRecord,
} from '@/lib/identity/client-store';
import type { KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';

const DEFAULT_POLL_INTERVAL_MS = 5_000;

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
    // pqSigningPublicKey omitted by design: the wire envelope + signature are classical (Flint #116410 —
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

/** Assemble the consume deps from an unlocked identity, or null if it's locked / has no armored key. */
export async function buildConsumeDeps(
  identity: unknown,
  opts: { fetchImpl?: typeof fetch } = {},
): Promise<ConsumeDeps | null> {
  const id = identity as { identity?: { fingerprint?: string; public_key?: string } } | null;
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
  };
  return {
    owner,
    decrypt: openpgpEnvelopeDecryptor(key.privateKey, key.passphrase),
    store: buildContactStore(fingerprint),
    emit: (e) => emitContactChange({ ids: [e.id], reason: 'live-apply' }),
    fetchImpl: opts.fetchImpl,
  };
}

export interface LiveBookPollHandle {
  stop: () => void;
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
  await consumeInboundContactUpdates(deps);
}

export function startLiveBookPolling(
  identity: unknown,
  opts: { intervalMs?: number; fetchImpl?: typeof fetch } = {},
): LiveBookPollHandle {
  const intervalMs = opts.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  let stopped = false;
  let inFlight = false;

  const tick = async () => {
    if (stopped || inFlight) return; // never overlap polls
    inFlight = true;
    try {
      const deps = await buildConsumeDeps(identity, { fetchImpl: opts.fetchImpl });
      if (!deps) return; // locked / no identity — stay static, retry next tick
      await consumeInboundContactUpdates(deps);
    } catch (err) {
      // local-only diagnostic; never surfaced to the peer/relay (I-1). One bad tick must not wedge the loop.
      console.error('[live-book-poll] poll tick failed (will retry):', err);
    } finally {
      inFlight = false;
    }
  };

  void tick(); // immediate first poll
  const timer = setInterval(() => void tick(), intervalMs);

  return {
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}
