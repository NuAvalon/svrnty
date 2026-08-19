// app/api/relay/ack/route.ts
// Return-channel ACK-DELETE. POST {mailbox_id, envelope_ids[], owner_ack} → owner-only delete of the
// listed envelopes (§5 §D). Ack-delete is the PRIMARY GC; the per-envelope TTL is the backstop.
//
// Owner-privileged: only R's key-holder may delete. Same owner-auth-first discipline as the poll —
// a non-owner takes the uniform 401 path and never mutates or probes the mailbox.

import { NextResponse } from 'next/server';
import { ackDelete } from '@/lib/relay/mailbox-store';
import { verifyMailboxAckAuth } from '@/lib/relay/mailbox-auth';

function nonOwner() {
  return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
}

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    const mailboxId = typeof body?.mailbox_id === 'string' ? body.mailbox_id : '';
    const envelopeIds: string[] = Array.isArray(body?.envelope_ids) ? body.envelope_ids : [];

    // Owner-auth binds the EXACT envelope_ids (the signed input includes them) — a tampered id-list
    // or a replayed poll-auth (different domain) fails here, before any store mutation.
    const now = Date.now();
    const isOwner = await verifyMailboxAckAuth(request, mailboxId, envelopeIds, now);
    if (!isOwner) return nonOwner();

    const deleted = ackDelete(mailboxId, envelopeIds, now);
    return NextResponse.json({ deleted });
  } catch {
    return nonOwner();
  }
}
