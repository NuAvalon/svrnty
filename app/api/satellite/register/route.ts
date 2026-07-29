// Proxy to satellite registration API
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

// Allowlist of fields we forward to the registration backend
const ALLOWED_FIELDS = ['fingerprint', 'public_key', 'name', 'email', 'slug'] as const;

export async function POST(request: NextRequest) {
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    // Only forward known fields — strip anything unexpected
    const body: Record<string, unknown> = {};
    for (const key of ALLOWED_FIELDS) {
      if (key in raw && typeof raw[key] === 'string' && raw[key].length <= 4096) {
        body[key] = raw[key];
      }
    }
    if (!body.fingerprint || !body.public_key) {
      return NextResponse.json({ error: 'fingerprint and public_key are required' }, { status: 400 });
    }
    const res = await fetch(`${SATELLITE_URL}/register`, {
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
