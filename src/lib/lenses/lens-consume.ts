// src/lib/lenses/lens-consume.ts
/**
 * Lenses v1.3 — the RECEIVE seam (contract R7). The mailbox's FIFTH inbound type: a lens payload is
 * sealed to the owner with the SAME hybrid mailbox envelope as contact.updates / notes / receipts,
 * so — exactly like those — it would decrypt NON-NULL via the contact-update decryptor and then be
 * dropped on its missing `envelope.fingerprint`. This seam routes it by its own type-checked opener
 * FIRST (uniform 'lens' cell + lens payload header), so a lens-capable client actually receives it.
 *
 * OLD-CLIENT SAFETY (R7): a client that does NOT wire this seam behaves exactly as before — the
 * lens cell opens to a 2048-byte binary plaintext that is not JSON, parseContactUpdateWire returns
 * null, and the envelope is terminally dropped as 'decrypt-failed'. It does not crash and it never
 * shows a partial card as complete. And a sender honoring R7 never sends 'methods' to a client that
 * has not HELLO'd — so old clients should never see one at all.
 *
 * SEAM SHAPE (mirrors the joiner / note / receipt seams):
 *   • verify — open + type-check the blob as a lens payload (hybrid sleeve → uniform cell → lens
 *     header). Returns the raw PAYLOAD bytes, or null for a non-lens blob (fall through unharmed —
 *     it can never eat a contact-update: a signed update is JSON, not a uniform cell). Does NOT
 *     authenticate — that's accept's job (the fp inside is attacker-chosen until the MAC verifies).
 *   • accept — whitelist-on-fetch (sender must be a known, unblocked contact) → derive the pair
 *     secret → verify the directional MAC (R4) → apply:
 *       - 'hello'   → record the peer as lens-capable in the device-local grants store (R7's signal).
 *       - 'methods' → replay-floor the seq (strictly-greater AND no more than a day ahead — a wrong
 *         clock must not poison the floor), then write the methods into the contact record's
 *         `contact_info.lens_methods` ONLY (upsert by kind+label — a payload REPLACES a key it
 *         carries and KEEPS a key it does not: "they keep what they already have", R6).
 *     Returns the outcome for the dispatcher; THROWS only on a store I/O failure (retryable).
 *
 * PRIMARY FIELDS ARE SIGNED-PATH TERRITORY (review-1 item 5): a lens value is authenticated by a
 * classical pair-MAC only, so applyLensMethods changes NO primary field — email, phones, urls and
 * handles all stay exactly as the signed path left them. Lens values live in lens_methods and are
 * SHOWN as given-by-them; a lens value that differs from the held signed value renders as CHANGED
 * with the contract copy (lens-display.ts), never silently as the contact's own.
 *
 * STORE BOUND (review-1 item 7): lens_methods is hard-capped at LENS_MAX_METHODS keys per contact —
 * a payload that would push the record past the cap is refused WHOLE (the record is left unchanged;
 * the seq floor still advances so the refusal is terminal, not retried forever). An admitted
 * contact on a modified client cannot inflate the record that rides every backup.
 *
 * The grants store here is the RECEIVER's copy of the same device-local namespace — it records only
 * which sender-fps announced capability and the inbound seq floor. No lens names ever arrive
 * (R1: the name stays on the SENDER's device — it is not in the payload).
 */

import { openLivingBookHybrid, resolveHybrid, type HybridSecretsSource } from '../crypto/living-book-sleeve';
import { admitContact } from '../trust/admit-contact';
import { getContactState } from '../trust/contact-state';
import { changedKeys, type ContactStore } from '../sync/consume-mailbox';
import type { StoredContact } from '../contacts/apply-contact-update';
import {
  LENS_KIND_HELLO,
  LENS_KIND_METHODS,
  LENS_MAX_METHODS,
  decodeLensMethodsBody,
  lensMethodKey,
  openLensPayload,
  parseLensPayload,
  unframeLensCell,
  type LensMethodWire,
} from './lens-wire';
import { acceptInSeq, markPeerCapable, type LensGrantBook } from './lens-grants';

/** The raw (unverified) payload bytes this seam hands from verify to accept. */
export type LensWireBytes = Uint8Array;

export interface LensSeam {
  verify: (blob: string) => Promise<LensWireBytes | null>;
  accept: (wire: LensWireBytes) => Promise<LensAcceptResult>;
}

export type LensAcceptResult =
  | { applied: true; id: string; fingerprint: string; ignited: boolean }
  | { hello: true }
  | { stale: true }
  /** R2a: the grant book read UNREADABLE — the MAC-verified payload was NOT applied and NOT
   *  dropped: it is HELD (bounded, in memory) and retried after the next good read. Terminal
   *  for the envelope — the consume loop acks it as a benign consume ('lens-held'). */
  | { held: true }
  /** R8a: terminal refusals on a MAC-VERIFIED payload, each with its own dead-letter reason —
   *  'method-cap' (lens_methods would grow past the cap; the contact gets the visible stopped
   *  state) and 'shared-slot' (two values in one kind+label slot). The fingerprint rides the
   *  RESULT to mark this as MAC-verified (vs a null silent drop) — and is dropped AT DISPATCH:
   *  the pair-MAC is classical-only, so the fp is not a signature-authenticated identity claim
   *  and never reaches a stored dead-letter row (see lensTerminalClass). */
  | { refused: 'method-cap' | 'shared-slot'; fingerprint: string }
  | null; // dropped: unverified (bad MAC / malformed), or a stranger/blocked sender — silent

/** R2b(b): the held-payload bound ACROSS contacts — at most this many senders' payloads wait in
 *  memory (each ≤ one uniform cell's payload, and one per contact — a contact cannot grow the
 *  hold by sending more). Past the cap a new sender's payload is dropped: bounded memory, never
 *  a plaintext write. */
export const LENS_HELD_MAX_SENDERS = 64;

export interface LensSeamDeps {
  /** The same contact store consume uses (lookup + persist). */
  store: ContactStore;
  /** The owner's hybrid open-material (as in living-book-sleeve; a lazy provider is fine). */
  hybridSecrets: HybridSecretsSource;
  /** The owner's IDENTITY fingerprint — the receiver leg of the pair-MAC context (NOT the mailbox fp:
   *  the MAC binds the two people's identity fps; the mailbox fp lives inside hybridSecrets). */
  ownerFingerprint: string;
  /** The pair secret per claimed sender (caller derives it from the identity keys). */
  sPairFor: (senderFingerprint: string) => Promise<Uint8Array | null> | Uint8Array | null;
  /** The device-local grants store (load/save the whole book). */
  loadGrants: () => LensGrantBook | Promise<LensGrantBook>;
  saveGrants: (book: LensGrantBook) => void | Promise<void>;
  /** ISO timestamp source (injected for determinism). */
  now?: () => string;
  /** Wall-clock seconds for the seq future-bound (injected for determinism). */
  nowSeconds?: () => number;
}

/** The lens_methods map from a contact record (empty object when absent/malformed). */
function lensMethodsOf(current: StoredContact): Record<string, LensMethodWire> {
  const ci = typeof current.contact_info === 'object' && current.contact_info !== null
    ? (current.contact_info as Record<string, unknown>)
    : {};
  return typeof ci.lens_methods === 'object' && ci.lens_methods !== null
    ? { ...(ci.lens_methods as Record<string, LensMethodWire>) }
    : {};
}

/**
 * Map a received method set onto the contact record. Exported for tests (pure).
 *
 * Writes ONLY contact_info.lens_methods — the faithful per-sender map, upserted by method key.
 * NO primary field (email, phone(s), urls, handles) is touched: those belong to the signed path,
 * and a lens value is only classical-MAC-authenticated — letting it overwrite the signed phone or
 * a swapped handle is the exact fraud this product exists against.
 *
 * Returns NULL (refuse the payload WHOLE, record unchanged) when the upsert would grow the map past
 * LENS_MAX_METHODS keys — the store bound keeps an admitted contact on a modified client from
 * inflating a record that rides every backup.
 */
export function applyLensMethods(current: StoredContact, methods: LensMethodWire[], now: string): StoredContact | null {
  const prev = lensMethodsOf(current);
  const keys = new Set(Object.keys(prev));
  for (const m of methods) keys.add(lensMethodKey(m));
  if (keys.size > LENS_MAX_METHODS) return null; // refused whole — the cap is per-contact total keys

  const ci: Record<string, unknown> =
    typeof current.contact_info === 'object' && current.contact_info !== null
      ? { ...(current.contact_info as Record<string, unknown>) }
      : {};
  delete ci.lens_stopped; // a payload that LANDS clears the R8a stopped state — updates resume
  const payloadKeys = new Set(methods.map(lensMethodKey));
  for (const m of methods) {
    const key = lensMethodKey(m);
    const prior = prev[key] as (LensMethodWire & { was?: string; wasKind?: boolean }) | undefined;
    const entry: LensMethodWire & { was?: string; wasKind?: boolean } = {
      kind: m.kind,
      value: m.value,
      ...(m.label !== undefined ? { label: m.label } : {}),
    };
    if (prior && prior.value !== m.value) {
      entry.was = prior.value; // R6a: same slot held a different value before — keep it for "Was:"
    } else if (!prior) {
      // R6b relabel-swap: a NEW slot whose kind drops a held value this payload does not carry —
      // the added value marks changed with the DROPPED value as "Was:", and the line names the
      // KIND (the label changed), not the new label.
      const dropped = Object.entries(prev).find(
        ([k, e]) => e && typeof e === 'object' && (e as LensMethodWire).kind === m.kind && !payloadKeys.has(k),
      );
      if (dropped) {
        const dv = (dropped[1] as LensMethodWire).value;
        if (typeof dv === 'string') { entry.was = dv; entry.wasKind = true; }
      }
    } else if (prior.was !== undefined) {
      entry.was = prior.was; // same value re-sent — the earlier change mark stands
      if (prior.wasKind === true) entry.wasKind = true;
    }
    prev[key] = entry;
  }
  ci.lens_methods = prev;

  // A verified lens payload is a real interaction — same decay-clock refresh as a signed update.
  return { ...current, contact_info: ci, last_interaction: now };
}

function stateOf(record: StoredContact) {
  const trusted =
    typeof record.trusted === 'boolean'
      ? record.trusted
      : record.trust_level === 'verified' || record.trust_level === 'trusted';
  const last_interaction =
    (typeof record.last_interaction === 'string' ? record.last_interaction : undefined) ||
    (typeof record.verified_at === 'string' ? record.verified_at : undefined) ||
    record.added_at;
  const decay_days = typeof record.decay_days === 'number' ? record.decay_days : 730;
  return getContactState({ trusted, last_interaction, decay_days } as Parameters<typeof getContactState>[0]);
}

/**
 * Compose the consume seam. The caller (live-book-poll / headless deps) wires it behind the flag.
 *
 * LIFETIME: keep ONE seam for the session (a poll loop's long-lived dep, not a per-envelope build):
 * the R2a held-payload table lives on the instance — a seam rebuilt between polls silently drops
 * what the unreadable-book window held. Memory-only by contract (never a plaintext persist), so a
 * restart still loses a held payload — bounded and documented, never a write.
 */
export function makeLensSeam(deps: LensSeamDeps): LensSeam {
  const now = deps.now ?? (() => new Date().toISOString());
  const nowSeconds = deps.nowSeconds ?? (() => Math.floor(Date.now() / 1000));

  /**
   * R2a/R2b — the HELD-PAYLOAD table. While the grant book reads unreadable, a MAC-VERIFIED
   * payload is not applied (nothing may write the book: no floor save, no capability mark — the
   * empty stand-in would be judged a floor of −1 and would then overwrite the real one). It is
   * held here instead and retried after the next good read — a transient read error costs a
   * delay, never a lost update and never a reset floor.
   *
   * Bounds (R2b): memory only (never a plaintext store), ONE entry per contact — the one with
   * the highest seq — plus LENS_HELD_MAX_SENDERS across contacts; a contact cannot grow the
   * hold by sending more. At apply time the held wire runs the FULL path again: a block,
   * untrust or remove made after the hold discards it, and it is judged against the real floor.
   */
  const heldPayloads = new Map<string, { wire: LensWireBytes; seq: number }>();
  let draining = false;

  const holdPayload = (fp: string, wire: LensWireBytes, seq: number): void => {
    const prev = heldPayloads.get(fp);
    if (prev) {
      if (seq > prev.seq) { prev.wire = wire; prev.seq = seq; } // one per contact: keep the highest seq
      return;
    }
    if (heldPayloads.size >= LENS_HELD_MAX_SENDERS) return; // total cap — bounded drop, never grows
    heldPayloads.set(fp, { wire, seq });
  };

  const route = async (raw: LensWireBytes): Promise<LensAcceptResult> => {
    // Structural parse — only to learn the CLAIMED sender for the book lookup (still untrusted).
    const claimed = parseLensPayload(raw);
    if (!claimed) return null;
    let contact = await deps.store.lookup(claimed.fpSender);
    if (!contact) return null; // custody whitelist-on-fetch: a stranger's lens is dropped unread
    if (!admitContact(contact.current)) return null; // a blocked sender has no channel at all
    const sPair = await deps.sPairFor(claimed.fpSender);
    if (!(sPair instanceof Uint8Array) || sPair.length !== 32) return null;
    const opened = openLensPayload(raw, { sPair, fpSender: claimed.fpSender, fpReceiver: deps.ownerFingerprint });
    if (!opened.ok) return null; // bad MAC / malformed / self — silent drop (I-1/I-2)
    if (opened.kind !== LENS_KIND_HELLO && opened.kind !== LENS_KIND_METHODS) return null;

    let book = await deps.loadGrants();
    if (book.unreadable === true) {
      holdPayload(claimed.fpSender, raw, opened.seq);
      return { held: true };
    }
    // On the FIRST good read, held payloads retry — this sender's first, because they arrived
    // before this wire: the floor must judge them first or the held one reads stale and an
    // update that should have cost a delay is lost. `draining` stops a held wire from re-entering
    // this block; each still does its own fresh book read above.
    if (!draining && heldPayloads.size > 0) {
      draining = true;
      try {
        const order = [...heldPayloads.keys()].sort((a, b) => (a === claimed.fpSender ? -1 : b === claimed.fpSender ? 1 : 0));
        for (const fp of order) {
          const h = heldPayloads.get(fp);
          if (!h) continue;
          heldPayloads.delete(fp);
          try {
            await route(h.wire); // the FULL path again — R2b(c) re-gates the contact as it is NOW
          } catch (err) {
            if (!heldPayloads.has(fp)) heldPayloads.set(fp, h); // a write failing mid-drain keeps it held
            throw err; // store I/O is retryable — the CURRENT envelope stays for the next poll too
          }
        }
      } finally {
        draining = false;
      }
      // The drain may have moved this sender's floor — or healed nothing. Re-read the book and
      // re-check custody before this wire is judged: its stored `before` could be stale.
      book = await deps.loadGrants();
      if (book.unreadable === true) {
        holdPayload(claimed.fpSender, raw, opened.seq);
        return { held: true };
      }
      contact = await deps.store.lookup(claimed.fpSender);
      if (!contact || !admitContact(contact.current)) return null;
    }

    if (opened.kind === LENS_KIND_HELLO) {
      const next = markPeerCapable(book, claimed.fpSender);
      if (next !== book) await deps.saveGrants(next);
      return { hello: true };
    }

    // methods: replay floor — strictly greater seq than the last accepted from this sender,
    // and no more than a day ahead of the local clock (a far-future seq poisons the floor).
    const floored = acceptInSeq(book, claimed.fpSender, opened.seq, nowSeconds());
    if (floored === null) return { stale: true };
    let methods: LensMethodWire[];
    try {
      methods = decodeLensMethodsBody(opened.body);
    } catch {
      return null; // a MAC-valid but undecodable body is dropped (the codec bounds already ran)
    }
    // R8a: one slot, one value — a payload carrying two values in one kind+label slot is refused
    // WHOLE under its own dead-letter reason (never silently keeping the last). Terminal: the
    // floor advances like every refusal, so it is not retried forever.
    if (new Set(methods.map(lensMethodKey)).size !== methods.length) {
      await deps.saveGrants(floored);
      return { refused: 'shared-slot', fingerprint: claimed.fpSender };
    }
    const before = contact.current;
    const next = applyLensMethods(before, methods, now());
    if (next === null) {
      // The payload would grow lens_methods past the cap — refused WHOLE under its own reason
      // (R8a), the floor still advances (this seq is SEEN; refusing it forever changes nothing),
      // AND the contact gets the visible stopped state — a silent stop reads like a Freeze or a
      // Remove nobody made, and a real change would never be seen to arrive.
      const ci = typeof before.contact_info === 'object' && before.contact_info !== null
        ? { ...(before.contact_info as Record<string, unknown>), lens_stopped: true }
        : { lens_stopped: true };
      await deps.store.persist(before.id, changedKeys(before, { ...before, contact_info: ci }));
      await deps.saveGrants(floored);
      return { refused: 'method-cap', fingerprint: claimed.fpSender };
    }
    const ignited = stateOf(before) === 'dim' && stateOf(next) === 'living';
    await deps.store.persist(before.id, changedKeys(before, next));
    await deps.saveGrants(floored);
    return { applied: true, id: before.id, fingerprint: claimed.fpSender, ignited };
  };

  return {
    verify: async (blob: string) => {
      const secrets = await resolveHybrid(deps.hybridSecrets);
      if (!secrets) return null; // cannot open hybrid yet — falls through (held upstream by the missing-key gate)
      const plaintext = await openLivingBookHybrid(blob, secrets.secrets, secrets.myFp);
      if (!plaintext) return null;
      const parsed = unframeLensCell(plaintext);
      if (!parsed) return null;
      // Hand the RAW unframed payload to accept — everything in it is attacker-chosen until the MAC verifies.
      const cell = plaintext;
      const len = new DataView(cell.buffer, cell.byteOffset, cell.byteLength).getUint32(2, false);
      return cell.slice(6, 6 + len);
    },
    accept: route,
  };
}
