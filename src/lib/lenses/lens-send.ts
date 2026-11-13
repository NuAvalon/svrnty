// src/lib/lenses/lens-send.ts
/**
 * Lenses v1.3 — the SEND composer for per-recipient lens payloads (contract R2/R5/R7/R9).
 *
 * SHAPE (mirrors send-contact-update.ts, deliberately):
 *   • PURE — returns {mailbox_id, blob} deposit tuples; the caller POSTs each to /api/relay/envelope.
 *   • ONE sealed payload PER RECIPIENT — each carries ONLY the methods of the lens THAT recipient
 *     holds, intersected with what they were already sent or confirmed to receive (the R3 gap fix:
 *     a lens edit that would expose a new method does not flow until the per-recipient widening
 *     confirm lands its key in the grant's `sent` set). The lens plays no part in the signed
 *     contact.update: lens methods NEVER go through buildAndSignContactUpdate and NEVER join
 *     CONTACT_UPDATE_ALLOWED_FIELDS (R9) — they travel only in this MAC'd, per-recipient schema.
 *   • THE SEND FILTER FAILS CLOSED (R2) — a recipient with NO record, an unreadable one, or a grant
 *     naming a deleted lens is sent ZERO methods: the update is HELD (no payload built, no seq
 *     bumped) and reported, so the sender sees it has not gone. There is NO default/tie-break face —
 *     a tie or a default never decides what a person gets.
 *   • THE GATE IS REQUIRED (R5) — `admit` is the existing RecipientGate (the book as it stands at
 *     send time). A blocked or removed recipient is skipped here; there is no second path around it.
 *   • CAPABILITY-GATED (R7) — 'methods' goes only to a recipient whose HELLO we have verified
 *     (peerIsCapable). Until then the payload is HELD — reported, so the sender can see it has not
 *     gone — never sent to a client that cannot take it.
 *   • FAIL-CLOSED PER RECIPIENT — no usable public key / no verified ML-KEM pubkey / an encode or
 *     seal error skips THAT recipient (reported) and never aborts the batch, and nothing is ever
 *     sent in a downgraded form. A lens whose body cannot fit one cell reports 'too-large' — the
 *     sender-facing copy for it lives in lens-copy.ts (LENS_TOO_LARGE_LINE); a person never sees
 *     "encode-failed".
 *
 * S_pair is provided by the caller (sPairFor) — derived from the identity keys elsewhere
 * (deriveSharedSecret(owner ed25519 seed, recipient ed25519 pub)); this module never touches key
 * material itself.
 */

import { deriveMailboxId } from '../relay/mailbox-auth';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import type { RecipientGate } from '../sync/contact-update-gate';
import type { OwnerCardBag, OwnerLens, OwnerMethod } from '../../components/identity/owner-card';
import {
  LENS_KIND_METHODS,
  LENS_KIND_HELLO,
  LENS_HELLO_BODY,
  LENS_MAX_BODY,
  buildLensCell,
  encodeLensMethodsBody,
  lensMethodKey,
  type LensMethodWire,
} from './lens-wire';
import { helloDue, lensForRecipient, lensSentKeys, markHelloSent, nextLensSeq, peerIsCapable, recordLensKeys, type LensGrantBook } from './lens-grants';
import { LENS_CAPABILITY_VERSION } from './lens-wire';

export interface LensRecipient {
  fingerprint: string;
  publicKeyArmored: string;
  /** The recipient's verified ML-KEM-1024 pubkey (base64). ABSENT ⇒ fail-closed skip ('no-pq-kem'). */
  pqKemPublicKey?: string;
}

export interface LensDeposit {
  mailbox_id: string;
  blob: string;
}

/** The complete skip-reason set (order stable — the sender-line map test iterates this array). */
export const LENS_SKIP_REASONS = [
  'bad-fingerprint',
  'blocked',
  'no-public-key',
  'no-pq-kem',
  'no-pair-secret',
  'too-large',
  'encode-failed',
  'encrypt-failed',
  'hello-throttled',
] as const;
export type LensSkipReason = (typeof LENS_SKIP_REASONS)[number];

/** The complete hold-reason set (order stable — the sender-line map test iterates this array). */
export const LENS_HOLD_REASONS = [
  /** No grant record, or a grant naming a deleted lens (R2): ZERO methods go — no payload is built
   *  and no seq is bumped. The sender assigns + confirms a lens to release. */
  'no-record',
  /** The grant book itself could not be read (corrupt, or a throwing store): same fail-closed hold,
   *  its own reason so the sender sees "the lenses couldn't be read" rather than "nothing is set". */
  'book-unreadable',
  /** The peer has not shown it can take lens payloads (R7). */
  'no-capability',
  /** Every method the lens would expose still awaits a widening confirm — nothing deliverable. */
  'unconfirmed',
  /** The granted lens resolves but exposes no methods at all — a zero-method payload would only
   *  leak that an update happened, so nothing is built (same "not an empty list sent" rule). */
  'empty-lens',
  /** R8a composer hold: the lens carries two methods in ONE slot (same kind AND label). The owner
   *  must label them first — never send a payload that silently keeps only the last. */
  'shared-slot',
] as const;
export type LensHoldReason = (typeof LENS_HOLD_REASONS)[number];

export interface LensSendPlan {
  deposits: LensDeposit[];
  skipped: Array<{ fingerprint: string; reason: LensSkipReason }>;
  /** Recipients whose payload was NOT sent: no record (R2) or no verified capability (R7). The
   *  sender's UI shows this as "hasn't gone" — the payload is held, never sent, and NO seq bumps. */
  held: Array<{ fingerprint: string; reason: LensHoldReason; methods?: LensMethodWire[] }>;
  /** Methods a recipient's current lens would expose that are NOT yet sent-or-confirmed — widenings
   *  awaiting the per-recipient confirm (the R3 gap). They were excluded from this send; the view
   *  prompts the confirm, which lands the keys in `sent` for the next one. */
  wideningPending: Array<{ fingerprint: string; methods: LensMethodWire[] }>;
  /** The grant book with this send's seq bumps + sent-set unions applied — the caller persists it. */
  book: LensGrantBook;
}

/**
 * Resolve the lens a send may draw on for this recipient: the lens their grant names, when that
 * lens still exists. NULL otherwise — no record, an unreadable record, or a grant naming a deleted
 * lens all resolve to null (R2 ruling: there is NO fallback face; zero methods go and the send
 * holds). Callers that only want "what face does this person currently get" use the same function —
 * a null answer renders as no face, never as a guessed one.
 */
export function lensForSend(bag: OwnerCardBag, book: LensGrantBook, recipientFingerprint: string): OwnerLens | null {
  const granted = lensForRecipient(book, recipientFingerprint);
  if (granted === null) return null;
  return bag.lenses.find((l) => l.id === granted) ?? null;
}

/** A send-side method: the wire fields PLUS the owner's method id — the id is the identity the
 *  sent set and the widening check key on (R3a); it never leaves the device (the wire carries
 *  kind+value+label only). */
export interface LensSendMethod extends LensMethodWire { id: string }

/** The method list for one lens: resolved, value-bearing, bounded at encode time. Each entry
 *  carries the owner's method id — R3a keys "sent" and "widening" on it, never on the wire slot. */
export function methodsForSend(bag: OwnerCardBag, lens: OwnerLens | null): LensSendMethod[] {
  if (!lens) return [];
  const byId = new Map(bag.methods.map((m: OwnerMethod) => [m.id, m]));
  const out: LensSendMethod[] = [];
  for (const id of lens.methodIds) {
    const m = byId.get(id);
    if (!m || !m.value.trim()) continue;
    const w: LensSendMethod = m.label?.trim()
      ? { id: m.id, kind: m.kind, value: m.value, label: m.label.trim() }
      : { id: m.id, kind: m.kind, value: m.value };
    out.push(w);
  }
  return out;
}

export interface BuildLensDepositsArgs {
  ownerFingerprint: string;
  bag: OwnerCardBag;
  book: LensGrantBook;
  recipients: LensRecipient[];
  /** The existing RecipientGate — REQUIRED (R5). A missing or throwing check refuses the whole batch. */
  admit: RecipientGate;
  /** The pair secret per recipient (caller derives it from the identity keys). null ⇒ 'no-pair-secret' skip. */
  sPairFor: (recipientFingerprint: string) => Promise<Uint8Array | null> | Uint8Array | null;
  /** Wall-clock seconds source for the seq anchor (review-1 item 4). Injected for determinism. */
  nowSeconds?: () => number;
}

/**
 * Build one sealed 'methods' deposit per capable, admitted, granted recipient. Each payload carries
 * only the recipient's sent-or-confirmed method keys; unconfirmed lens methods are reported in
 * wideningPending and stay behind. Returns the plan AND the updated grant book for the caller to
 * persist — a recipient's row changes (seq bump + sent union) only when their payload was built.
 */
export async function buildLensDeposits(args: BuildLensDepositsArgs): Promise<LensSendPlan> {
  if (typeof args.admit !== 'function') throw new Error('refusing to send a lens payload without a recipient check');
  const nowSeconds = args.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
  const deposits: LensDeposit[] = [];
  const skipped: LensSendPlan['skipped'] = [];
  const held: LensSendPlan['held'] = [];
  const wideningPending: LensSendPlan['wideningPending'] = [];
  let book = args.book;

  for (const r of args.recipients) {
    const fp = String(r?.fingerprint ?? '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fp)) {
      skipped.push({ fingerprint: String(r?.fingerprint), reason: 'bad-fingerprint' });
      continue;
    }
    if (!args.admit(fp)) {
      skipped.push({ fingerprint: fp, reason: 'blocked' }); // R5: the gate is the only path
      continue;
    }
    if (book.unreadable === true) {
      held.push({ fingerprint: fp, reason: 'book-unreadable' }); // corrupt/unreadable book: same fail-closed hold, own reason
      continue;
    }
    const lens = lensForSend(args.bag, book, fp);
    if (lens === null) {
      held.push({ fingerprint: fp, reason: 'no-record' }); // R2: zero methods go — held, shown, no seq bump
      continue;
    }
    if (typeof r.publicKeyArmored !== 'string' || r.publicKeyArmored.length === 0) {
      skipped.push({ fingerprint: fp, reason: 'no-public-key' });
      continue;
    }
    if (typeof r.pqKemPublicKey !== 'string' || r.pqKemPublicKey.length === 0) {
      skipped.push({ fingerprint: fp, reason: 'no-pq-kem' });
      continue;
    }
    if (!peerIsCapable(book, fp)) {
      held.push({ fingerprint: fp, reason: 'no-capability' }); // R7: hold, show the sender it hasn't gone
      continue;
    }
    const sPair = await args.sPairFor(fp);
    if (!(sPair instanceof Uint8Array) || sPair.length !== 32) {
      skipped.push({ fingerprint: fp, reason: 'no-pair-secret' });
      continue;
    }
    const lensMethods = methodsForSend(args.bag, lens);
    // R8a composer hold: one slot, one value. Two methods sharing a kind AND label in this lens
    // hold the send — the owner labels them first; a payload can never silently keep only the last.
    const seen = new Set<string>();
    const shared = lensMethods.filter((m) => {
      const k = lensMethodKey(m);
      if (seen.has(k)) return true;
      seen.add(k);
      return false;
    });
    if (shared.length) {
      held.push({ fingerprint: fp, reason: 'shared-slot', methods: shared });
      continue;
    }
    // The R3-gap filter (R3a: keyed by the owner's METHOD id, never the wire slot): only methods
    // already sent or confirmed flow; the rest are widenings awaiting the per-recipient confirm —
    // reported, never sent (a lens edit cannot widen anyone silently).
    const sent = lensSentKeys(book, fp);
    const allowed = lensMethods.filter((m) => sent.has(m.id));
    const pending = lensMethods.filter((m) => !sent.has(m.id));
    if (pending.length) wideningPending.push({ fingerprint: fp, methods: pending });
    if (allowed.length === 0) {
      held.push({ fingerprint: fp, reason: pending.length ? 'unconfirmed' : 'empty-lens' });
      continue;
    }
    let cell: Uint8Array;
    let sentKeys: string[];
    try {
      const body = encodeLensMethodsBody(allowed);
      if (body.length > LENS_MAX_BODY) {
        skipped.push({ fingerprint: fp, reason: 'too-large' }); // sender copy: lensTooLargeLine
        continue;
      }
      const next = nextLensSeq(book, fp, nowSeconds());
      cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: args.ownerFingerprint, fpReceiver: fp, seq: next.seq, body, sPair });
      book = next.book;
      sentKeys = allowed.map((m) => m.id);
    } catch {
      skipped.push({ fingerprint: fp, reason: 'encode-failed' });
      continue;
    }
    try {
      const blob = await sealLivingBookHybrid(cell, r.publicKeyArmored, r.pqKemPublicKey);
      deposits.push({ mailbox_id: deriveMailboxId(fp), blob });
      book = recordLensKeys(book, fp, sentKeys); // last-sent ∪ confirmed — union only, never un-disclose
    } catch {
      skipped.push({ fingerprint: fp, reason: 'encrypt-failed' });
    }
  }

  return { deposits, skipped, held, wideningPending, book };
}

/**
 * The "can take it" signal (R7): a sealed HELLO to an admitted contact, announcing this client takes
 * lens payloads. It rides the SAME sealed mailbox path and the SAME 2048B uniform cell — invisible
 * to the relay and shape-identical to a 'methods' payload. A HELLO needs no capability check (it IS
 * the signal) and carries seq 0 (idempotent; receive-side floors apply to 'methods' only).
 */
export async function buildLensHelloDeposits(args: {
  ownerFingerprint: string;
  recipients: LensRecipient[];
  admit: RecipientGate;
  sPairFor: BuildLensDepositsArgs['sPairFor'];
  /** R7a: the sealed grant book — carries the per-contact "hello sent" marker (budget: one hello
   *  per capability version + one retry after the envelope life). The caller persists the book. */
  book: LensGrantBook;
  nowSeconds?: () => number;
}): Promise<{ deposits: LensDeposit[]; skipped: Array<{ fingerprint: string; reason: LensSkipReason | 'book-unreadable' }>; book: LensGrantBook }> {
  if (typeof args.admit !== 'function') throw new Error('refusing to send a lens hello without a recipient check');
  const nowSeconds = args.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
  const deposits: LensDeposit[] = [];
  const skipped: Array<{ fingerprint: string; reason: LensSkipReason | 'book-unreadable' }> = [];
  let book = args.book;
  for (const r of args.recipients) {
    const fp = String(r?.fingerprint ?? '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fp)) { skipped.push({ fingerprint: String(r?.fingerprint), reason: 'bad-fingerprint' }); continue; }
    if (!args.admit(fp)) { skipped.push({ fingerprint: fp, reason: 'blocked' }); continue; }
    // R2a: an unreadable book is READ-ONLY — no hello is built from it and no marker is written;
    // the book returns untouched so a persisting caller (guarded by saveLensGrants anyway) saves nothing.
    if (book.unreadable === true) { skipped.push({ fingerprint: fp, reason: 'book-unreadable' }); continue; }
    if (!helloDue(book, fp, LENS_CAPABILITY_VERSION, nowSeconds())) { skipped.push({ fingerprint: fp, reason: 'hello-throttled' }); continue; }
    if (typeof r.publicKeyArmored !== 'string' || !r.publicKeyArmored) { skipped.push({ fingerprint: fp, reason: 'no-public-key' }); continue; }
    if (typeof r.pqKemPublicKey !== 'string' || !r.pqKemPublicKey) { skipped.push({ fingerprint: fp, reason: 'no-pq-kem' }); continue; }
    const sPair = await args.sPairFor(fp);
    if (!(sPair instanceof Uint8Array) || sPair.length !== 32) { skipped.push({ fingerprint: fp, reason: 'no-pair-secret' }); continue; }
    try {
      const cell = buildLensCell({ kind: LENS_KIND_HELLO, fpSender: args.ownerFingerprint, fpReceiver: fp, seq: 0, body: LENS_HELLO_BODY, sPair });
      const blob = await sealLivingBookHybrid(cell, r.publicKeyArmored, r.pqKemPublicKey);
      deposits.push({ mailbox_id: deriveMailboxId(fp), blob });
      book = markHelloSent(book, fp, LENS_CAPABILITY_VERSION, nowSeconds()); // R7a: the marker is what rations the next call
    } catch {
      skipped.push({ fingerprint: fp, reason: 'encrypt-failed' });
    }
  }
  return { deposits, skipped, book };
}

/** POST each deposit to the relay — the drop-in mirroring sendContactUpdate's POST loop. */
export async function sendLensDeposits(
  deposits: LensDeposit[],
  opts: { fetchImpl?: typeof fetch; relayBase?: string } = {},
): Promise<{ deposited: string[]; failed: Array<{ mailbox_id: string; status: number | string }> }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const relayBase = opts.relayBase ?? '/api/relay';
  const deposited: string[] = [];
  const failed: Array<{ mailbox_id: string; status: number | string }> = [];
  for (const d of deposits) {
    try {
      const res = await doFetch(`${relayBase}/envelope`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mailbox_id: d.mailbox_id, blob: d.blob }),
      });
      if (res.ok) deposited.push(d.mailbox_id);
      else failed.push({ mailbox_id: d.mailbox_id, status: res.status });
    } catch {
      failed.push({ mailbox_id: d.mailbox_id, status: 'network-error' });
    }
  }
  return { deposited, failed };
}
