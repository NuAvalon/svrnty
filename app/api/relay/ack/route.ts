// app/api/relay/ack/route.ts
// Return-channel ACK-DELETE. POST {mailbox_id, envelope_ids[], owner_ack} → owner-only delete of the
// listed envelopes (§5 §D). Ack-delete is the PRIMARY GC; the per-envelope TTL is the backstop.
//
// Owner-privileged: only R's key-holder may delete. Same owner-auth-first discipline as the poll —
// a non-owner takes the uniform 401 path and never mutates or probes the mailbox.

import { NextResponse } from 'next/server';
import { ackDelete } from '@/lib/relay/mailbox-store';
import { verifyOwnerAuth } from '@/lib/relay/owner-auth';

function nonOwner() {
  return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
}

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    const mailboxId = body?.mailbox_id;
    const envelopeIds = body?.envelope_ids;

    const isOwner = await verifyOwnerAuth(request, mailboxId);
    if (!isOwner) return nonOwner();

    if (!Array.isArray(envelopeIds)) {
      return NextResponse.json({ error: 'invalid envelope_ids' }, { status: 400 });
    }
    const deleted = ackDelete(mailboxId, envelopeIds, Date.now());
    return NextResponse.json({ deleted });
  } catch {
    return nonOwner();
  }
}
