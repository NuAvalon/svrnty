// Same-origin proxy for the satellite /onion DEPOSIT endpoint (S6 consent-delta / #558 keystone).
//
// The client (httpOnionRelay.deposit, src/lib/sync/consent-delta-transport.ts) POSTs ONE onion-sealed
// OUTER cell — a MailboxEnvelopePackage {v,alg,mailbox_fp,epk,kem_ct,nonce,ct} (mailbox-envelope.ts, via
// sealOnion). The satellite peels the OUTER with its OWN routing keypair and buckets the (still
// device-sealed) inner by the route_id it finds inside (KB#91430: peel → deposit-by-route_id,
// uniform-400 on peel-fail, no oracle). This proxy MUST forward the sealed envelope OPAQUE and strip
// NOTHING — stripping is precisely the #179 failure (the PSI proxy allowlist reduced a sealed body to {}
// → satellite 400 → silent delivery failure for every contact). A go-private consent-delta deposit that
// silently can't leave the client is the exact survivor-safety harm the fleet refused to ship.
//
// ★ SHARED DISCIPLINE: this allowlist is the inline twin of pickSealedEnvelope in
//   src/lib/sync/psi-proxy-body.ts (#179). Kept inline here (register/route.ts style — single fixed-path
//   endpoint, no catch-all) so this PR stays independently mergeable. #556 (wire-format) changes the
//   envelope shape and MUST update BOTH this allowlist and psi-proxy-body.ts in lockstep, or a field
//   silently stops forwarding. Folding the two into one shared helper is a #556-time cleanup.
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

// MailboxEnvelopePackage string fields (mailbox-envelope.ts:39). `v` is the numeric literal 1 and is
// handled explicitly below; everything else is opaque base64/hex.
const ENVELOPE_STRING_KEYS = ['alg', 'mailbox_fp', 'epk', 'kem_ct', 'nonce', 'ct'] as const;
// Required for a well-formed outer cell — a deposit missing any of these can't be peeled; reject at the
// proxy (fast, no satellite round-trip) rather than forward a malformed cell. This is pure shape
// validation — it reveals nothing about peel success/recipient, so it introduces no peel-oracle; the
// satellite's uniform-400 is relayed through verbatim below.
const REQUIRED_STRING_KEYS = ['alg', 'epk', 'kem_ct', 'nonce', 'ct'] as const;

const MAX_STRING_LEN = 8192;
// `ct` carries the AES-256-GCM ciphertext of the whole onion OUTER plaintext ({route, inner}, where the
// inner is itself a sealed envelope with a ~2KB ML-KEM ct) — an order of magnitude above the per-field
// cap, not unbounded.
const MAX_CT_LEN = 1_048_576;

function pickOnionCell(raw: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (raw.v === 1) body.v = 1;
  for (const key of ENVELOPE_STRING_KEYS) {
    const value = raw[key];
    if (typeof value !== 'string') continue;
    const cap = key === 'ct' ? MAX_CT_LEN : MAX_STRING_LEN;
    if (value.length <= cap) body[key] = value;
  }
  return body;
}

export async function POST(request: NextRequest) {
  try {
    let raw: unknown;
    try {
      raw = await request.json();
    } catch {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    const body = pickOnionCell(raw as Record<string, unknown>);
    if (body.v !== 1 || REQUIRED_STRING_KEYS.some((k) => typeof body[k] !== 'string')) {
      return NextResponse.json({ error: 'Invalid onion cell' }, { status: 400 });
    }

    const res = await fetch(`${SATELLITE_URL}/onion`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    try {
      return NextResponse.json(JSON.parse(text), { status: res.status });
    } catch {
      return new NextResponse(text, { status: res.status });
    }
  } catch {
    return NextResponse.json({ error: 'Onion relay unavailable' }, { status: 502 });
  }
}
