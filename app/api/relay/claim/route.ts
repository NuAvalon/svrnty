// app/api/relay/claim/route.ts
// Layer (A) beta-access CLAIM — POST {token} + owner-auth header → mark the owner's DUMB mailbox
// "claimed" (= "has messaging"). Format §3 5-step verify, fail-closed + UNIFORM reject (never leak
// which step failed — same anti-oracle discipline as the poll). The claim ONLY flips claimed-status;
// it does NOT touch the mailbox store → buffered deposits deliver RETROACTIVELY once the owner can poll
// (criterion-1, no-flush). The claim-registry stores status-only (criterion-2).

import { NextResponse } from 'next/server';
import { deriveMailboxId, verifyMailboxClaimAuth } from '@/lib/relay/mailbox-auth';
import { decodeBetaAccessToken, verifyBetaAccessToken, type PinnedIssuer } from '@/lib/relay/beta-access';
import { isJtiRedeemed, recordClaim } from '@/lib/relay/claim-registry';

// Uniform reject — identical for every verify failure (bad token / bad issuer / bad owner-auth /
// claims-disabled). An attacker can't tell which gate rejected. 200 only on a resolved claim.
function reject() {
  return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
}

/** The relay's pinned issuer trust-root (format §4), from env. Null = beta-claims disabled (fail-closed). */
function pinnedIssuer(): PinnedIssuer | null {
  const fingerprint = process.env.SVRNTY_BETA_ISSUER_FP;
  const publicKeyArmored = process.env.SVRNTY_BETA_ISSUER_PUBKEY;
  if (!fingerprint || !publicKeyArmored) return null;
  const pqB64 = process.env.SVRNTY_BETA_ISSUER_PQ_SIG_PUBKEY;
  let pqSigningPublicKey: Uint8Array | undefined;
  if (pqB64) {
    try {
      const bin = atob(pqB64);
      const b = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
      pqSigningPublicKey = b;
    } catch {
      return null; // a misconfigured PQ pin fails CLOSED (no claims) rather than silently classical-only
    }
  }
  return { fingerprint, publicKeyArmored, pqSigningPublicKey };
}

export async function POST(request: Request) {
  try {
    const issuer = pinnedIssuer();
    if (!issuer) return reject(); // no issuer pinned → beta-claims disabled, fail-closed

    const body = await request.json().catch(() => null);
    const wire = typeof body?.token === 'string' ? body.token : '';
    const token = decodeBetaAccessToken(wire);
    if (!token) return reject(); // malformed token

    const now = Date.now();

    // §3.1 + §3.4-exp: issuer-signed by the PINNED issuer + not expired.
    const verdict = await verifyBetaAccessToken(token, issuer, now);
    if (!verdict.ok) return reject();

    // §3.2 + §3.3 (unified via the mailbox_id binding): owner-auth is checked against
    // mailbox_id = deriveMailboxId(token.sub). verifyMailboxClaimAuth passes IFF the claimer controls a
    // key whose fp derives THIS mailbox_id — i.e. deriveMailboxId(bundle.fp) == deriveMailboxId(sub).
    // deriveMailboxId is SHA256 (injective-in-practice), so that binds bundle.fp == token.sub = §3.3.
    // This is what makes the token NON-TRANSFERABLE: a leaked token is useless without sub's key.
    const mailboxId = deriveMailboxId(token.sub);
    const ownerOk = await verifyMailboxClaimAuth(request, mailboxId, now);
    if (!ownerOk) return reject();

    // §3.5: idempotent. Re-presenting a seen jti (or a second token) for an already-owner-authed mailbox
    // is a no-op that still reads claimed. (jti one-time ACROSS mailboxes is enforced by §3.2+§3.3 — a
    // jti can only ever be presented for its own sub's mailbox.) Record + confirm.
    const alreadyJti = isJtiRedeemed(mailboxId, token.jti);
    recordClaim(mailboxId, token.jti);
    return NextResponse.json({ status: 'claimed', idempotent: alreadyJti });
  } catch {
    return reject(); // never throw — a verifier refuses uniformly
  }
}
