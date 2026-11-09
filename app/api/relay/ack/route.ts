// app/api/relay/ack/route.ts
// Return-channel ACK-DELETE. POST {mailbox_id, envelope_ids[], owner_ack} → owner-only delete of the
// listed envelopes (§5 §D). Ack-delete is the PRIMARY GC; the per-envelope TTL is the backstop.
//
// Owner-privileged: only R's key-holder may delete. Same owner-auth-first discipline as the poll —
// a non-owner takes the uniform 401 path and never mutates or probes the mailbox.

import { NextResponse } from 'next/server';
import { ownerRouteGate } from '@/lib/relay/owner-route-budget';
import { mailboxConfig } from '@/lib/relay/mailbox-config';
import { ackDelete } from '@/lib/relay/mailbox-store';
import { readJsonCapped } from '@/lib/relay/read-body-capped';
import { verifyMailboxAckAuth } from '@/lib/relay/mailbox-auth';
import { isMailboxIdV2, verifyOwnerRequestV2 } from '@/lib/relay/mailbox-auth-v2';

function nonOwner() {
  return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
}

export async function POST(request: Request) {
  // Per-IP budget FIRST, before the URL, the body or any auth header is parsed: a refused request never reaches a verifier, and
  // the refusal (uniform 429) is decided before the mailbox id is read, so it can't vary on R (I-4).
  const gated = ownerRouteGate(request);
  if (gated) return gated;
  try {
    const body = await readJsonCapped(request, mailboxConfig().maxPayloadBytes);
    const mailboxId = typeof body?.mailbox_id === 'string' ? body.mailbox_id : '';
    const envelopeIds: string[] = Array.isArray(body?.envelope_ids) ? body.envelope_ids : [];

    // Owner-auth binds the EXACT envelope_ids (the signed input includes them) — a tampered id-list
    // or a replayed poll-auth (different domain) fails here, before any store mutation.
    const now = Date.now();
    // #721: version by the id itself; the other version's bundle fails on the uniform path.
    const isOwner = isMailboxIdV2(mailboxId)
      ? mailboxConfig().ownerV2Enabled && (await verifyOwnerRequestV2(request, 'ack', mailboxId, now, envelopeIds)) // refused unless enabled: no client signs v2 yet, see mailbox-config.ts
      : await verifyMailboxAckAuth(request, mailboxId, envelopeIds, now);
    if (!isOwner) return nonOwner();

    const deleted = ackDelete(mailboxId, envelopeIds, now);
    return NextResponse.json({ deleted });
  } catch {
    return nonOwner();
  }
}
