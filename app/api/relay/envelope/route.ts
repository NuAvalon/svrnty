// app/api/relay/envelope/route.ts
// Return-channel DEPOSIT. POST {mailbox_id, blob} → UNIFORM ack (I-4 deposit-side): the response
// reveals nothing about R's mailbox state (exists/empty/full). Any writer may deposit (demo:
// rate-limited); the relay verifies NO sender identity (that's content-auth inside the opaque blob).
// Sibling of the single-use relay at ../route.ts — the dead-drop is left untouched.

import { NextResponse } from 'next/server';
import { depositEnvelope } from '@/lib/relay/mailbox-store';
import { mailboxConfig } from '@/lib/relay/mailbox-config';
import { checkMailboxRateLimit, getClientIP } from '@/lib/relay/mailbox-rate-limit';
import { relayDiskFull } from '@/lib/relay/disk-watermark';
import { dbPath } from '@/lib/relay/mailbox-store';
import { logDeposit429 } from '@/lib/relay/deposit-429-log';
import { readBodyCapped } from '@/lib/relay/read-body-capped';
import { isValidMailboxId } from '@/lib/relay/mailbox-id';
import { chargeDepositBudget, depositCharge, depositBudgetAllows } from '@/lib/relay/deposit-budget';

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
      logDeposit429('rate_limit', now);
      return NextResponse.json({ error: 'Rate limit exceeded.' }, { status: 429 });
    }

    // L4: a global refusal while the data filesystem is above the watermark. 429 so the sender sees a definite "Not sent" (Hypatia
    // #2204); never per-mailbox. Polls and acks are not affected (they free the disk).
    if (relayDiskFull(dbPath(), now)) {
      logDeposit429('disk_full', now);
      return NextResponse.json({ error: 'Relay storage full.' }, { status: 429 });
    }

    // Content-Length is optional, so the cap above can't be the only one: stop reading once a body passes it.
    const raw = await readBodyCapped(request, cfg.maxPayloadBytes);
    if (raw === null) return NextResponse.json({ error: 'Payload too large.' }, { status: 413 });
    let body: { mailbox_id?: unknown; blob?: unknown } | null = null;
    try { body = JSON.parse(new TextDecoder().decode(raw)); } catch { /* falls through to the 400 below */ }
    const mailboxId = body?.mailbox_id;
    const blob = body?.blob;
    if (!isValidMailboxId(mailboxId)) return NextResponse.json({ error: 'Missing or invalid field.' }, { status: 400 });

    // One budget for everyone: refusing for the rest of this window beats filling the disk and refusing until the TTLs expire. Never per-mailbox (I-4).
    const blobBytes = typeof blob === 'string' ? Buffer.byteLength(blob) : 0;
    const charge = depositCharge(blobBytes);
    if (!depositBudgetAllows(charge, now)) {
      logDeposit429('global_budget', now);
      return NextResponse.json({ error: 'Relay busy.' }, { status: 429 });
    }

    const result = depositEnvelope(mailboxId, blob as string, now);
    if (!result.ok) {
      if (result.status === 429) {
        logDeposit429('mailbox_cap', now);
        return NextResponse.json({ error: 'Mailbox at capacity.' }, { status: 429 });
      }
      if (result.status === 413) return NextResponse.json({ error: 'Payload too large.' }, { status: 413 });
      return NextResponse.json({ error: 'Missing or invalid field.' }, { status: 400 });
    }
    chargeDepositBudget(charge, now);
    return NextResponse.json(UNIFORM_ACK);
  } catch {
    return NextResponse.json({ error: 'Failed to deposit.' }, { status: 500 });
  }
}
