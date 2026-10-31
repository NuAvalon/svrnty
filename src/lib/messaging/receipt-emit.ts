// src/lib/messaging/receipt-emit.ts
// S62 slice 3 (contract v6 C1-C6): the RECIPIENT side of "Delivered". After a note has been durably STORED, answer its sender with a
// designated-verifier MAC receipt, sealed hybrid to the sender's mailbox. Best-effort and never throws: a receipt is a bonus on top of an
// already-persisted note and must not be able to fail it.
//
// What this refuses to do, each pinned by a test:
//  - emit for anything that is not a note wire, or whose receipt_key is absent / not 64 hex (old clients, hostile or uniform-frame traffic);
//  - downgrade: a sender with no ML-KEM key (a classical identity) gets NO receipt, never a classical one;
//  - read the claimed sender off an unauthenticated wire: the caller only ever passes a wire that acceptInboundNote ACCEPTED, so
//    from_fingerprint / public_key / pq_kem_public_key are signature-bound (verifyNoteSender) and admitted;
//  - log or return the key or the tag.

import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { NOTE_WIRE_TYPE } from './domains';
import { buildReceiptWireV1 } from './receipt-wire-v1';
import { sealReceiptV1To } from './seal';
import type { NoteWireV0 } from './types';

export type EmitOutcome = 'sent' | 'skipped' | 'failed';
const POST_TIMEOUT_MS = 8000;

export async function emitDeliveredReceipt(wire: NoteWireV0, opts: { fetchImpl?: typeof fetch; relayBase?: string; postTimeoutMs?: number } = {}): Promise<EmitOutcome> {
  try {
    if (wire.type !== NOTE_WIRE_TYPE) return 'skipped';
    if (!wire.public_key || !wire.pq_kem_public_key || !wire.from_fingerprint) return 'skipped'; // no downgrade, no addressing without a bound key
    const receipt = buildReceiptWireV1(wire.receipt_key, wire.note_id, 'delivered');
    if (!receipt) return 'skipped';
    const blob = await sealReceiptV1To(receipt, wire.public_key, wire.pq_kem_public_key);
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        abort.abort();
        reject(new Error('timeout'));
      }, opts.postTimeoutMs ?? POST_TIMEOUT_MS);
    });
    const posted = (opts.fetchImpl ?? fetch)(`${opts.relayBase ?? '/api/relay'}/envelope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mailbox_id: deriveMailboxId(wire.from_fingerprint), blob }),
      signal: abort.signal,
    });
    posted.catch(() => {});
    try {
      const res = await Promise.race([posted, timedOut]);
      return res.ok ? 'sent' : 'failed';
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return 'failed'; // never the message, never a key: a receipt that cannot be sent is simply not sent
  }
}
