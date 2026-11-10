// src/lib/lenses/lens-send.ts
/**
 * Lenses v1.3 — the SEND composer for per-recipient lens payloads (contract R2/R5/R7/R9).
 *
 * SHAPE (mirrors send-contact-update.ts, deliberately):
 *   • PURE — returns {mailbox_id, blob} deposit tuples; the caller POSTs each to /api/relay/envelope.
 *   • ONE sealed payload PER RECIPIENT — each carries ONLY the methods of the lens THAT recipient
 *     holds. The lens plays no part in the signed contact.update: lens methods NEVER go through
 *     buildAndSignContactUpdate and NEVER join CONTACT_UPDATE_ALLOWED_FIELDS (R9) — they travel
 *     only in this MAC'd, per-recipient schema.
 *   • THE SEND FILTER FAILS CLOSED (R2) — a recipient with no grant record gets the NARROWEST
 *     face: the lens exposing the fewest methods (the default lens wins ties). A grant naming a
 *     deleted lens, or a corrupt record, resolves exactly the same way.
 *   • THE GATE IS REQUIRED (R5) — `admit` is the existing RecipientGate (the book as it stands at
 *     send time). A blocked or removed recipient is skipped here; there is no second path around it.
 *   • CAPABILITY-GATED (R7) — 'methods' goes only to a recipient whose HELLO we have verified
 *     (peerIsCapable). Until then the payload is HELD — reported, so the sender can see it has not
 *     gone — never sent to a client that cannot take it.
 *   • FAIL-CLOSED PER RECIPIENT — no usable public key / no verified ML-KEM pubkey / an encode or
 *     seal error skips THAT recipient (reported) and never aborts the batch, and nothing is ever
 *     sent in a downgraded form.
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
  buildLensCell,
  encodeLensMethodsBody,
  type LensMethodWire,
} from './lens-wire';
import { lensForRecipient, nextLensSeq, peerIsCapable, type LensGrantBook } from './lens-grants';

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

export type LensSkipReason =
  | 'bad-fingerprint'
  | 'blocked'
  | 'no-public-key'
  | 'no-pq-kem'
  | 'no-pair-secret'
  | 'encode-failed'
  | 'encrypt-failed';

export type LensHoldReason = 'no-capability';

export interface LensSendPlan {
  deposits: LensDeposit[];
  skipped: Array<{ fingerprint: string; reason: LensSkipReason }>;
  /** Recipients whose payload was built-class but NOT sent (R7): they have not shown they can take
   *  it. The sender's UI shows this as "hasn't gone" — the payload is held, never sent. */
  held: Array<{ fingerprint: string; reason: LensHoldReason }>;
  /** The grant book with this send's seq bumps applied — the caller persists it. */
  book: LensGrantBook;
}

/**
 * R2 — the narrowest face: the lens exposing the fewest resolvable methods. The default lens wins
 * ties (it is the face the owner chose to hand out by default); absent all lenses, the empty face.
 * THIS IS THE FAIL-CLOSED FLOOR: a recipient with no record, a corrupt record, or a record naming a
 * lens that no longer exists resolves HERE — never to a wider face.
 */
export function narrowestLens(bag: OwnerCardBag): OwnerLens | null {
  if (!bag || !Array.isArray(bag.lenses) || bag.lenses.length === 0) return null;
  const count = (l: OwnerLens) =>
    l.methodIds.reduce((n, id) => {
      const m = bag.methods.find((x) => x.id === id);
      return m && m.value.trim() ? n + 1 : n;
    }, 0);
  let best: OwnerLens | null = null;
  for (const l of bag.lenses) {
    if (best === null) best = l;
    else if (count(l) < count(best)) best = l;
    else if (count(l) === count(best) && l.id === bag.defaultLensId) best = l;
  }
  return best;
}

/** Resolve a recipient's lens: their grant's lens if it still exists, else the narrowest face (R2). */
export function lensForSend(bag: OwnerCardBag, book: LensGrantBook, recipientFingerprint: string): OwnerLens | null {
  const granted = lensForRecipient(book, recipientFingerprint);
  if (granted !== null) {
    const lens = bag.lenses.find((l) => l.id === granted);
    if (lens) return lens; // a grant naming a deleted lens falls through to the floor
  }
  return narrowestLens(bag);
}

/** The wire method list for one lens: resolved, value-bearing, bounded at encode time. */
export function methodsForSend(bag: OwnerCardBag, lens: OwnerLens | null): LensMethodWire[] {
  if (!lens) return [];
  const byId = new Map(bag.methods.map((m: OwnerMethod) => [m.id, m]));
  const out: LensMethodWire[] = [];
  for (const id of lens.methodIds) {
    const m = byId.get(id);
    if (!m || !m.value.trim()) continue;
    out.push(m.label?.trim() ? { kind: m.kind, value: m.value, label: m.label.trim() } : { kind: m.kind, value: m.value });
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
}

/**
 * Build one sealed 'methods' deposit per capable, admitted recipient. Returns the plan AND the
 * seq-bumped grant book for the caller to persist — even a partially-failed send bumps only the
 * recipients whose payload was actually built (the bumped seq is written on success only).
 */
export async function buildLensDeposits(args: BuildLensDepositsArgs): Promise<LensSendPlan> {
  if (typeof args.admit !== 'function') throw new Error('refusing to send a lens payload without a recipient check');
  const deposits: LensDeposit[] = [];
  const skipped: LensSendPlan['skipped'] = [];
  const held: LensSendPlan['held'] = [];
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
    const lens = lensForSend(args.bag, book, fp); // R2: record || narrowest face
    let cell: Uint8Array;
    try {
      const body = encodeLensMethodsBody(methodsForSend(args.bag, lens));
      const next = nextLensSeq(book, fp);
      cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: args.ownerFingerprint, fpReceiver: fp, seq: next.seq, body, sPair });
      book = next.book;
    } catch {
      skipped.push({ fingerprint: fp, reason: 'encode-failed' });
      continue;
    }
    try {
      const blob = await sealLivingBookHybrid(cell, r.publicKeyArmored, r.pqKemPublicKey);
      deposits.push({ mailbox_id: deriveMailboxId(fp), blob });
    } catch {
      skipped.push({ fingerprint: fp, reason: 'encrypt-failed' });
    }
  }

  return { deposits, skipped, held, book };
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
}): Promise<{ deposits: LensDeposit[]; skipped: LensSendPlan['skipped'] }> {
  if (typeof args.admit !== 'function') throw new Error('refusing to send a lens hello without a recipient check');
  const deposits: LensDeposit[] = [];
  const skipped: LensSendPlan['skipped'] = [];
  for (const r of args.recipients) {
    const fp = String(r?.fingerprint ?? '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fp)) { skipped.push({ fingerprint: String(r?.fingerprint), reason: 'bad-fingerprint' }); continue; }
    if (!args.admit(fp)) { skipped.push({ fingerprint: fp, reason: 'blocked' }); continue; }
    if (typeof r.publicKeyArmored !== 'string' || !r.publicKeyArmored) { skipped.push({ fingerprint: fp, reason: 'no-public-key' }); continue; }
    if (typeof r.pqKemPublicKey !== 'string' || !r.pqKemPublicKey) { skipped.push({ fingerprint: fp, reason: 'no-pq-kem' }); continue; }
    const sPair = await args.sPairFor(fp);
    if (!(sPair instanceof Uint8Array) || sPair.length !== 32) { skipped.push({ fingerprint: fp, reason: 'no-pair-secret' }); continue; }
    try {
      const cell = buildLensCell({ kind: LENS_KIND_HELLO, fpSender: args.ownerFingerprint, fpReceiver: fp, seq: 0, body: LENS_HELLO_BODY, sPair });
      const blob = await sealLivingBookHybrid(cell, r.publicKeyArmored, r.pqKemPublicKey);
      deposits.push({ mailbox_id: deriveMailboxId(fp), blob });
    } catch {
      skipped.push({ fingerprint: fp, reason: 'encrypt-failed' });
    }
  }
  return { deposits, skipped };
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
