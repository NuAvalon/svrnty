// app/api/relay/envelope/route.ts
// Return-channel DEPOSIT. POST {mailbox_id, blob} → UNIFORM ack (I-4 deposit-side): the response
// reveals nothing about R's mailbox state (exists/empty/full). Any writer may deposit (demo:
// rate-limited); the relay verifies NO sender identity (that's content-auth inside the opaque blob).
// Sibling of the single-use relay at ../route.ts — the dead-drop is left untouched.

import { NextResponse } from 'next/server';
import { depositEnvelope } from '@/lib/relay/mailbox-store';
import { mailboxConfig } from '@/lib/relay/mailbox-config';
import { checkMailboxRateLimit, getClientIP } from '@/lib/relay/mailbox-rate-limit';

// The uniform deposit ack — identical for every mailbox state (I-4). Never varies on R.
const UNIFORM_ACK = { status: 'queued' as const };

export async function POST(request: Request) {
  try {
    const cfg = mailboxConfig();
    const now = Date.now();

    const contentLength = request.headers.get('content-length');
    if (contentLength && Number.parseInt(contentLength, 10) > cfg.maxPayloadBytes) {
      return NextResponse.json({ error: 'Payload too large.' }, { status: 413 });
    }

    // Per-IP rate limit (about the depositor, not R's mailbox — uniform w.r.t. R).
    if (!checkMailboxRateLimit(getClientIP(request), now)) {
      return NextResponse.json({ error: 'Rate limit exceeded.' }, { status: 429 });
    }

    const body = await request.json().catch(() => null);
    const mailboxId = body?.mailbox_id;
    const blob = body?.blob;

    const result = depositEnvelope(mailboxId, blob, now);
    if (!result.ok) {
      if (result.status === 429) return NextResponse.json({ error: 'Mailbox at capacity.' }, { status: 429 });
      if (result.status === 413) return NextResponse.json({ error: 'Payload too large.' }, { status: 413 });
      return NextResponse.json({ error: 'Missing or invalid field.' }, { status: 400 });
    }
    return NextResponse.json(UNIFORM_ACK);
  } catch {
    return NextResponse.json({ error: 'Failed to deposit.' }, { status: 500 });
  }
}
