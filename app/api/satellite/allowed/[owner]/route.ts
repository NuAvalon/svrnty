// Same-origin proxy for satellite POST /allowed/{owner} — the PSI-discovery consent write.
// Allowlisted body only ({sender_fingerprint, signature}); the owner is a path param. Never forwards
// device-local fields. Models app/api/satellite/register/route.ts + the trust/psi proxy's async params.
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const SHORT_MAX = 4096;
const OWNER_RE = /^[A-Za-z0-9_-]+$/; // fingerprint chars only — no slashes / dots / path traversal
const ALLOWED_FIELDS = ['sender_fingerprint', 'signature'] as const;

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ owner: string }> },
) {
  try {
    const { owner } = await params;
    if (!owner || owner.length > 128 || !OWNER_RE.test(owner)) {
      return NextResponse.json({ error: 'Invalid owner fingerprint' }, { status: 400 });
    }
    const raw = await request.json();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    const source = raw as Record<string, unknown>;
    const body: Record<string, unknown> = {};
    for (const key of ALLOWED_FIELDS) {
      const v = source[key];
      if (typeof v === 'string' && v.length <= SHORT_MAX) body[key] = v;
    }
    if (!body.sender_fingerprint || !body.signature) {
      return NextResponse.json(
        { error: 'sender_fingerprint and signature are required' },
        { status: 400 },
      );
    }
    const res = await fetch(`${SATELLITE_URL}/allowed/${encodeURIComponent(owner)}`, {
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
    return NextResponse.json({ error: 'Allowed-sender service unavailable' }, { status: 502 });
  }
}
