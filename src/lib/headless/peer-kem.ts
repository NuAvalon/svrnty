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
  return `NOT SENT to ${hex8(peerFingerprint)}: ${reason}`;
}

/**
 * The stderr line for a send the relay did NOT take with a 2xx. The status class decides the claim:
 *  - 5xx / 408: the relay may have stored it before it failed. UNCONFIRMED, and the line says resending could deliver it twice ("NOT SENT" here would invite a duplicate).
 *  - any other status (4xx incl. 429): the relay looked at it and stored nothing. NOT SENT.
 *  - no status: nothing was posted, so NOT SENT.
 * The status is named, so a person (or the C9 failover rule) can tell a refusal from an outage. `tail` is the caller's local-state note
 * (e.g. that a ratchet index is spent).
 */
export function depositFailureLine(peerFingerprint: string, status: number | undefined, tail = ''): string {
  const t = tail ? `; ${tail}` : '';
  if (status !== undefined && (status >= 500 || status === 408)) {
    return formatUnconfirmed(peerFingerprint, `the relay answered HTTP ${status}; it may or may not be in their mailbox${t}`);
  }
  if (status !== undefined) return formatNotSent(peerFingerprint, `the relay refused the deposit (HTTP ${status}); nothing was stored${t}`);
  return formatNotSent(peerFingerprint, `the relay did not accept the deposit${t}`);
}

/** A send that did not get a clean answer from the relay but may have been stored: never worded "NOT SENT" (a re-send would duplicate).
 *  Every UNCONFIRMED line ends with the same sentence, added HERE so no caller can leave it off; `reason` carries no final full stop. */
export function formatUnconfirmed(peerFingerprint: string, reason: string): string {
  return `UNCONFIRMED to ${hex8(peerFingerprint)}: ${reason}. Resending could deliver it twice.`;
}

function hex8(peerFingerprint: string): string {
  return (peerFingerprint.match(/^[0-9a-fA-F]+/)?.[0] ?? '').slice(0, 8).toLowerCase() || '?';
}

/** One bounded line from a thrown send error (e.g. undici's `fetch failed`), so it can sit inside a
 *  NOT SENT line without a newline or an unbounded message breaking the one-line contract. Every control
 *  byte (ESC, BEL, NUL, DEL, CR/LF...) becomes a space first: a thrown message may carry relay-supplied
 *  text, and an escape sequence must not ride stderr into a poller or a terminal pane (Flint #478). */
export function errorLine(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  return m.replace(/[\x00-\x1f\x7f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120) || 'unknown error';
}

/** Where a thrown send stopped. sendNoteFromHeadless signs + seals, POSTs, THEN writes the local copy, so
 *  a throw means different things at each point: only the first three mean "nothing was delivered". */
export type SendStage = 'before-post' | 'unreachable' | 'refused' | 'deposited';

/** Wrap fetch so a caller can tell, after a throw, how far the send got. 'deposited' = the relay answered 2xx
 *  (the note IS in the mailbox, whatever threw afterwards); 'refused' = it answered non-2xx; 'unreachable' =
 *  the request itself threw; 'before-post' = no request was ever made (sign/seal threw first). */
export function trackedFetch(base: typeof fetch): { fetchImpl: typeof fetch; stage: () => SendStage } {
  let stage: SendStage = 'before-post';
  const fetchImpl = (async (...a: Parameters<typeof fetch>) => {
    stage = 'unreachable';
    const res = await base(...a);
    stage = res.ok ? 'deposited' : 'refused';
    return res;
  }) as typeof fetch;
  return { fetchImpl, stage: () => stage };
}

/** The ONE stderr line for a send that THREW, worded by what actually happened. Three prefixes, and a
 *  wrapper must treat them differently:
 *    NOT SENT    = PROVEN not delivered (nothing left, or the relay answered non-2xx): safe to retry.
 *    DEPOSITED   = the relay accepted it (only the local copy failed): do NOT resend.
 *    UNCONFIRMED = the request threw, so the relay may or may not have stored it (a connection can die
 *                  AFTER the relay stored the note): non-zero exit, and a wrapper must NOT auto-retry.
 *  `ratchetIndexSpent` is for send-tr (the chain advanced before the call). */
export function sendThrowLine(peerFingerprint: string, e: unknown, stage: SendStage, ratchetIndexSpent = false): string {
  const msg = errorLine(e);
  const spent = ratchetIndexSpent ? '; this ratchet index is spent' : '';
  if (stage === 'deposited') {
    return `DEPOSITED to ${hex8(peerFingerprint)}, but saving the local copy failed (${msg}); do NOT resend`;
  }
  if (stage === 'unreachable') {
    return formatUnconfirmed(peerFingerprint, `no response from the relay (${msg}); it may or may not be in their mailbox${spent}`);
  }
  const why = stage === 'refused' ? 'the relay did not accept the deposit, and saving the local copy failed'
    : 'the send failed before reaching the relay';
  return formatNotSent(peerFingerprint, `${why} (${msg})${spent}`);
}
