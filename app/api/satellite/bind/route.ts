// Proxy to satellite /bind (raw Ed25519 auth-key binding, tag#3 PSI auth). Allowlisted fields only.
//
// Field names match the DEPLOYED satellite /bind contract (confirmed from its own Pydantic 422, which
// requires `sig_pubkey` + `binding_sig` and rejects the old `sign_pubkey`/`signature`): the satellite
// BindRequest = { fingerprint, sig_pubkey, nonce, epoch, binding_sig } where
//   binding_sig = Ed25519( IDENTITY priv, "svrnty-bind:{sig_pubkey_hex}:{nonce_hex}:{epoch}" ).
// The prior allowlist forwarded sign_pubkey/signature → the satellite stripped-view 422'd "Field
// required: sig_pubkey/binding_sig" → NO bind could pass through this proxy. Dark until
// isPSIDiscoveryLive flips. (The GET-challenge handler below is vestigial — the deployed satellite /bind
// is POST-only and self-nonce'd; reconciling runBindCeremony to POST-direct is the paired client fix.)
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const POST_FIELDS = ['fingerprint', 'sig_pubkey', 'nonce', 'epoch', 'binding_sig'] as const;

export async function GET(request: NextRequest) {
  try {
    const fingerprint = request.nextUrl.searchParams.get('fingerprint') || '';
    if (!fingerprint || fingerprint.length > 256) {
      return NextResponse.json({ error: 'fingerprint is required' }, { status: 400 });
    }
    const res = await fetch(
      `${SATELLITE_URL}/bind?fingerprint=${encodeURIComponent(fingerprint)}`,
    );
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: 'Registration service unavailable' }, { status: 502 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    const body: Record<string, unknown> = {};
    for (const key of POST_FIELDS) {
      const value = raw[key];
      if (typeof value === 'string' && value.length <= 8192) body[key] = value;
      else if (key === 'epoch' && typeof value === 'number' && Number.isFinite(value)) body[key] = value;
    }
    if (!body.fingerprint || !body.sig_pubkey || !body.binding_sig) {
      return NextResponse.json({ error: 'fingerprint, sig_pubkey, and binding_sig are required' }, { status: 400 });
    }
    const res = await fetch(`${SATELLITE_URL}/bind`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: 'Registration service unavailable' }, { status: 502 });
  }
}
