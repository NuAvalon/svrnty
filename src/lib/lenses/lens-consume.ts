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
 *       - 'methods' → replay-floor the seq, then write the methods onto the contact record: the
 *         faithful set lives in `contact_info.lens_methods` (upsert by kind+label — a payload
 *         REPLACES a key it carries and KEEPS a key it does not: "they keep what they already
 *         have", R6) and the displayable subset mirrors into the homes the card view already
 *         renders (handles / urls / emails / phones, derived from that map).
 *     Returns the outcome for the dispatcher; THROWS only on a store I/O failure (retryable).
 *
 * The grants store here is the RECEIVER's copy of the same device-local namespace — it records only
 * which sender-fps announced capability and the inbound seq floor. No lens names ever arrive
 * (R1: the name stays on the SENDER's device — it is not in the payload).
 */

import { openLivingBookHybrid, resolveHybrid, type HybridSecretsSource } from '../crypto/living-book-sleeve';
import { admitContact } from '../trust/admit-contact';
import { getContactState } from '../trust/contact-state';
import { CONTACT_HANDLE_KEYS, HANDLE_VALUE_MAX_LEN } from '../trust/contact-update';
import { changedKeys, type ContactStore } from '../sync/consume-mailbox';
import type { StoredContact } from '../contacts/apply-contact-update';
import {
  LENS_KIND_HELLO,
  LENS_KIND_METHODS,
  decodeLensMethodsBody,
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
  | null; // dropped: unverified (bad MAC / malformed), or a stranger/blocked sender — silent

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
}

/** Map a received method set onto the contact record. Exported for tests (pure). */
export function applyLensMethods(current: StoredContact, methods: LensMethodWire[], now: string): StoredContact {
  const ci: Record<string, unknown> =
    typeof current.contact_info === 'object' && current.contact_info !== null
      ? { ...(current.contact_info as Record<string, unknown>) }
      : {};

  // The faithful record: keyed `${kind} ${label}` → latest value. Upsert per payload; a key
  // the payload does not carry persists (R6 — the recipient keeps what they were already given).
  const prev: Record<string, LensMethodWire> =
    typeof ci.lens_methods === 'object' && ci.lens_methods !== null
      ? { ...(ci.lens_methods as Record<string, LensMethodWire>) }
      : {};
  for (const m of methods) {
    prev[`${m.kind} ${m.label ?? ''}`] = {
      kind: m.kind,
      value: m.value,
      ...(m.label !== undefined ? { label: m.label } : {}),
    };
  }
  ci.lens_methods = prev;

  // Mirror the displayable subset into the homes the card view renders — derived FROM the map, so
  // an update replaces its key and a kept entry stays shown (the receiver-side "keep what you have").
  const entries = Object.values(prev);
  const handles: Record<string, string> =
    typeof ci.handles === 'object' && ci.handles !== null ? { ...(ci.handles as Record<string, string>) } : {};
  for (const e of entries) {
    if (CONTACT_HANDLE_KEYS.has(e.kind) && e.value.length <= HANDLE_VALUE_MAX_LEN) handles[e.kind] = e.value;
  }
  if (Object.keys(handles).length) ci.handles = handles;
  const urls = entries.filter((e) => e.kind === 'site' || e.kind === 'url' || e.kind === 'website').map((e) => e.value);
  if (urls.length) ci.urls = [...new Set(urls)];
  const emails = entries.filter((e) => e.kind === 'email').map((e) => e.value);
  const phones = entries.filter((e) => e.kind === 'phone').map((e) => e.value);

  const next: StoredContact = { ...current, contact_info: ci };
  if (emails.length) {
    next.emails = [...new Set(emails)];
    next.email = emails[0];
  }
  if (phones.length) {
    next.phones = [...new Set(phones)];
    next.phone = phones[0];
  }

  // A verified lens payload is a real interaction — same decay-clock refresh as a signed update.
  next.last_interaction = now;
  return next;
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

/** Compose the consume seam. The caller (live-book-poll / headless deps) wires it behind the flag. */
export function makeLensSeam(deps: LensSeamDeps): LensSeam {
  const now = deps.now ?? (() => new Date().toISOString());
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
    accept: async (raw: LensWireBytes) => {
      // Structural parse — only to learn the CLAIMED sender for the book lookup (still untrusted).
      const claimed = parseLensPayload(raw);
      if (!claimed) return null;
      const contact = await deps.store.lookup(claimed.fpSender);
      if (!contact) return null; // custody whitelist-on-fetch: a stranger's lens is dropped unread
      if (!admitContact(contact.current)) return null; // a blocked sender has no channel at all
      const sPair = await deps.sPairFor(claimed.fpSender);
      if (!(sPair instanceof Uint8Array) || sPair.length !== 32) return null;
      const opened = openLensPayload(raw, { sPair, fpSender: claimed.fpSender, fpReceiver: deps.ownerFingerprint });
      if (!opened.ok) return null; // bad MAC / malformed / self — silent drop (I-1/I-2)

      if (opened.kind === LENS_KIND_HELLO) {
        const book = await deps.loadGrants();
        const next = markPeerCapable(book, claimed.fpSender);
        if (next !== book) await deps.saveGrants(next);
        return { hello: true };
      }
      if (opened.kind !== LENS_KIND_METHODS) return null;

      // methods: replay floor — strictly greater seq than the last accepted from this sender.
      const book = await deps.loadGrants();
      const floored = acceptInSeq(book, claimed.fpSender, opened.seq);
      if (floored === null) return { stale: true };
      let methods: LensMethodWire[];
      try {
        methods = decodeLensMethodsBody(opened.body);
      } catch {
        return null; // a MAC-valid but undecodable body is dropped (the codec bounds already ran)
      }
      const before = contact.current;
      const next = applyLensMethods(before, methods, now());
      const ignited = stateOf(before) === 'dim' && stateOf(next) === 'living';
      await deps.store.persist(before.id, changedKeys(before, next));
      await deps.saveGrants(floored);
      return { applied: true, id: before.id, fingerprint: claimed.fpSender, ignited };
    },
  };
}
