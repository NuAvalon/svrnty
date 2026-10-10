// Proxy to satellite registration. Forwards the four public keys the satellite
// re-hashes into the identity fingerprint. Never forwards email.
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const SHORT_MAX = 4096;
const KEY_HEX_MAX = 16384; // ML-DSA-87 pubkey hex is 5184 chars
const ALLOWED_FIELDS = [
  'fingerprint',
  'public_key',
  'name',
  'slug',
  'sign_pub',
  'enc_pub',
  'kem_pub',
  'sig_pub',
] as const;

export async function POST(request: NextRequest) {
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    const body: Record<string, unknown> = {};
    for (const key of ALLOWED_FIELDS) {
      const max = key.endsWith('_pub') ? KEY_HEX_MAX : SHORT_MAX;
      if (key in raw && typeof raw[key] === 'string' && raw[key].length <= max) {
        body[key] = raw[key];
      }
    }
    if (typeof raw.display_name === 'string' && raw.display_name.length <= 256 && !body.name) {
      body.name = raw.display_name;
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
