// src/lib/messaging/dead-letter-store.ts
// #720: the local dead-letter records (contract v2/v3 R2 = Flint F2). One METADATA-ONLY row per envelope that did not become a stored
// message, kept as an encrypted row in the notes DB's 'settings' store (no schema bump; see store.ts). Never the blob, never any text
// from it, never a sender the device did not authenticate. A record is committed BEFORE the relay is told to delete the envelope.

import { deleteEncryptedSetting, getEncryptedSetting, listEncryptedSettings, putEncryptedSetting } from './store';
import { heldCountFor, parseDeadLetterRow, planPrune, resetMarksFor, safeEnvelopeId, type DeadLetterRow } from '@/lib/sync/dead-letter';

const PREFIX = 'dead_letter:';

function keyFor(envelopeId: string): string {
  const id = safeEnvelopeId(envelopeId);
  if (!id) throw new Error('unsafe envelope id');
  return `${PREFIX}${id}`;
}

/**
 * Commit (or update) the record for one envelope. THROWS if the row is invalid or the store is locked/unwritable: the caller must then
 * keep the envelope on the relay, never ack it. An existing record keeps its EARLIEST first_seen (the bound counts from the first poll
 * that saw the envelope, not the latest).
 */
export async function putDeadLetter(row: DeadLetterRow): Promise<void> {
  const clean = parseDeadLetterRow(row);
  if (!clean) throw new Error('invalid dead-letter row');
  const key = keyFor(clean.envelope_id);
  const prev = parseDeadLetterRow(await getEncryptedSetting<unknown>(key));
  const first_seen = prev && Date.parse(prev.first_seen) < Date.parse(clean.first_seen) ? prev.first_seen : clean.first_seen;
  await putEncryptedSetting(key, { ...clean, first_seen } satisfies DeadLetterRow);
}

export async function getDeadLetter(envelopeId: string): Promise<DeadLetterRow | null> {
  return parseDeadLetterRow(await getEncryptedSetting<unknown>(keyFor(envelopeId)));
}

/** All valid records, oldest first. A row that fails validation, or whose key and envelope_id disagree, is skipped. */
export async function listDeadLetters(): Promise<DeadLetterRow[]> {
  const out: DeadLetterRow[] = [];
  for (const { key, value } of await listEncryptedSettings<unknown>(PREFIX)) {
    const row = parseDeadLetterRow(value);
    if (row && key === `${PREFIX}${row.envelope_id}`) out.push(row);
  }
  return out.sort((a, b) => Date.parse(a.first_seen) - Date.parse(b.first_seen) || (a.envelope_id < b.envelope_id ? -1 : 1));
}

/** How many frames from this contact are held right now (the reset dialog's count). */
export async function countHeldFor(peerFp: string): Promise<number> {
  return heldCountFor(await listDeadLetters(), peerFp);
}

/**
 * R2: turn this contact's held ratchet rows into session-reset records. Returns how many. Idempotent (a second call finds none held).
 * Call it AFTER the session row was deleted: if marking fails the frames simply stay held and a repeated reset marks them; the other order
 * could release frames for a reset that then failed.
 */
export async function markSessionReset(peerFp: string): Promise<number> {
  const marks = resetMarksFor(await listDeadLetters(), peerFp);
  for (const m of marks) await putDeadLetter(m);
  return marks.length;
}

/** The envelopes a reset released, by record key -> the contact's fp. Read ONCE per poll: the poll acks them without opening them. */
export async function releasedByReset(): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const r of await listDeadLetters()) if (r.reason === 'session-reset' && r.fp) out.set(r.envelope_id, r.fp);
  return out;
}

/** Clear the record once the message opens (R5: the message replaces the flag). */
export async function removeDeadLetter(envelopeId: string): Promise<void> {
  await deleteEncryptedSetting(keyFor(envelopeId));
}

/** Enforce row retention. Returns how many were removed. Never throws into a caller that is mid-poll: callers treat it as best effort. */
export async function pruneDeadLetters(nowMs: number): Promise<number> {
  const rows = await listDeadLetters();
  const drop = planPrune(rows, nowMs);
  for (const id of drop) await removeDeadLetter(id);
  return drop.length;
}
