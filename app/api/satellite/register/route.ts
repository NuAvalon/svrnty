// Proxy to satellite registration. Forwards the four public keys the satellite
// re-hashes into the identity fingerprint. Never forwards email.
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const SHORT_MAX = 4096;
const KEY_MATERIAL_MAX = 16384; // base64 of ML-DSA-87 (2592B) = 3456 chars; hex was 5184 — 16384 covers both
// Satellite RegisterRequest contract (satellite.py): base64 raw pubkeys under these EXACT names
// + crypto_version. The old sign_pub/enc_pub/kem_pub/sig_pub matched no backend decoder and were
// stripped here / ignored downstream → register-400. Keep the allowlist and the client builder
// (buildSatelliteRegisterFields) in lockstep with the satellite schema.
const ALLOWED_FIELDS = [
  'fingerprint',
  'public_key',
  'name',
  'slug',
  'encryption_pk',
  'pq_kem_pk',
  'pq_sig_pk',
  'crypto_version',
] as const;
const KEY_MATERIAL_FIELDS = new Set<string>(['public_key', 'encryption_pk', 'pq_kem_pk', 'pq_sig_pk']);

export async function POST(request: NextRequest) {
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    const body: Record<string, unknown> = {};
    for (const key of ALLOWED_FIELDS) {
      const max = KEY_MATERIAL_FIELDS.has(key) ? KEY_MATERIAL_MAX : SHORT_MAX;
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
