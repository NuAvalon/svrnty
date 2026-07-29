// Proxy to satellite slug claim API
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

// Slug: lowercase alphanumeric + hyphens/underscores, 3-40 chars
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{2,39}$/;

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ name: string }> }
) {
  try {
    const { name } = await params;
    // Validate slug to prevent path traversal / injection
    if (!SLUG_RE.test(name)) {
      return NextResponse.json({ error: 'Invalid slug format' }, { status: 400 });
    }
    const raw = await request.json();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    // Only forward known fields
    const body: Record<string, unknown> = {};
    if (typeof raw.fingerprint === 'string' && raw.fingerprint.length <= 256) body.fingerprint = raw.fingerprint;
    if (typeof raw.public_key === 'string' && raw.public_key.length <= 4096) body.public_key = raw.public_key;
    if (typeof raw.signature === 'string' && raw.signature.length <= 4096) body.signature = raw.signature;
    if (!body.fingerprint) {
      return NextResponse.json({ error: 'fingerprint is required' }, { status: 400 });
    }
    const res = await fetch(`${SATELLITE_URL}/slug/${encodeURIComponent(name)}/claim`, {
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
