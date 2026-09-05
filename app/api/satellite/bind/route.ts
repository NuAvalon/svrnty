// Proxy to satellite /bind (raw Ed25519 sign-key binding). Allowlisted fields only.
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const POST_FIELDS = ['fingerprint', 'sign_pubkey', 'nonce', 'epoch', 'signature'] as const;

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
    if (!body.fingerprint || !body.sign_pubkey || !body.signature) {
      return NextResponse.json({ error: 'fingerprint, sign_pubkey, and signature are required' }, { status: 400 });
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
