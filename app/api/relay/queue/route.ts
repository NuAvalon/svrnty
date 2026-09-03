// app/api/relay/queue/route.ts
// Return-channel POLL. GET ?mailbox_id=… → owner-only, NON-destructive list [{envelope_id, blob}].
//
// I-4 ANTI-EXISTENCE-ORACLE (the load-bearing gate): owner-auth is verified FIRST, before any store
// access, so a non-owner never reaches the store and the response cannot depend on the mailbox's
// existence/occupancy. owner-auth-fail ≡ no-mailbox ≡ empty — one code path, identical bytes+status
// +latency (joint §5 §C; no 404-vs-expired two-latency split reproduced here).

import { NextResponse } from 'next/server';
import { pollMailbox } from '@/lib/relay/mailbox-store';
import { verifyMailboxPollAuth } from '@/lib/relay/mailbox-auth';

// The single uniform non-owner response — computed WITHOUT touching the store, so its latency and
// bytes are independent of any mailbox's state. It never contains a stored blob.
function nonOwner() {
  return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const mailboxId = searchParams.get('mailbox_id') ?? '';

    // Owner check precedes ALL store access. Non-owners (incl. no-auth / bad-auth) take the uniform
    // path below and never learn whether the mailbox exists.
    const isOwner = await verifyMailboxPollAuth(request, mailboxId, Date.now());
    if (!isOwner) return nonOwner();

    // Authenticated owner only: an absent mailbox reads as empty ([]), which the owner already knows.
    const list = pollMailbox(mailboxId, Date.now());
    return NextResponse.json(list);
  } catch {
    // Even on error, return the uniform non-owner shape — never leak state via an error path.
    return nonOwner();
  }
}
