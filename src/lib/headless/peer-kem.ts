// src/lib/headless/peer-kem.ts
//
// Where a headless SENDER gets the recipient's ML-KEM-1024 key (Flint #180833 rules, #456).
//
// sendNoteFromHeadless seals PQ-hybrid only when it is handed `peerPqKemPublicKey`, and otherwise
// deposits NOTHING (fail-closed, never a classical downgrade). The agent CLI (scripts/devin-comm.ts)
// used to pass none, so after S14 a send silently came back deposited:false. This module is the ONE
// place that decides what kem a send may use, and its rules are deliberately narrow:
//
//   1. The kem comes from the ADMITTED contact record, and from nowhere else. The function takes the
//      stored contact and nothing more: no argv, no env, no inbound wire, no card handed in at send
//      time. A key that did not pass admission is not a key we seal to.
//   2. The record's kem (and sig) legs must still hash to the contact's fingerprint at SEND time
//      (fingerprintMatchesKey: canonical four-key hash), so a record that was edited, or a kem swapped
//      in beside a valid fingerprint, is refused rather than sealed to.
//   3. Every refusal is a NAMED reason the caller prints as `NOT SENT to <8hex>: <reason>` and exits
//      non-zero on. There is no silent path and no "deposited" claim without a deposit.
import { fingerprintMatchesKey } from '../identity/fingerprint';
import type { HeadlessContact } from './headless-store';

export type PeerKemResolution =
  | { ok: true; kem: string }
  | { ok: false; reason: string };

/** Resolve the PQ key a send to `contact` may seal with. Pure of any I/O except the local key hash. */
export async function resolvePeerKemForSend(
  contact: Pick<HeadlessContact, 'fingerprint' | 'public_key' | 'pq_kem_public_key' | 'pq_sig_public_key'> | null | undefined,
): Promise<PeerKemResolution> {
  if (!contact) return { ok: false, reason: 'not an admitted contact' };
  if (!contact.pq_kem_public_key) {
    return { ok: false, reason: 'no PQ key on file: ask them to re-share their card' };
  }
  // The canonical fingerprint hashes sign|enc|kem|sig: without the record's sig leg the kem cannot be
  // checked against the fingerprint, so an incomplete record is a refusal, not a pass.
  if (!contact.pq_sig_public_key) {
    return { ok: false, reason: 'no PQ signing key on file, so the PQ key cannot be checked: ask them to re-share their card' };
  }
  const bound = await fingerprintMatchesKey(contact.fingerprint, contact.public_key, {
    kem_public_key: contact.pq_kem_public_key,
    sig_public_key: contact.pq_sig_public_key,
  });
  if (!bound) {
    return { ok: false, reason: 'the PQ key on file does not match their fingerprint: do not send; ask them to re-share their card' };
  }
  return { ok: true, kem: contact.pq_kem_public_key };
}

/** The single stderr line a refused (or not-deposited) send prints. Only a hex prefix of the
 *  fingerprint is echoed, so an operator-typed argument can never inject text into the line. */
export function formatNotSent(peerFingerprint: string, reason: string): string {
  const hex = (peerFingerprint.match(/^[0-9a-fA-F]+/)?.[0] ?? '').slice(0, 8).toLowerCase() || '?';
  return `NOT SENT to ${hex}: ${reason}`;
}

/** One bounded line from a thrown send error (e.g. undici's `fetch failed`), so it can sit inside a
 *  NOT SENT line without a newline or an unbounded message breaking the one-line contract. */
export function errorLine(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  return m.replace(/\s+/g, ' ').trim().slice(0, 120) || 'unknown error';
}
