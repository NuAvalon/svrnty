// Proxy to the registration service's /verify — the CANONICAL account-creation endpoint
// (option-B: re-derives the full-64 hybrid DID SHA256(sign‖enc‖kem‖sig), INSERTs the
// verified identity, propagates to the satellite). Mirrors register/route.ts.
//
// OPEN mint (blueprint §Identity; Peter #135459 / Archie #135495): NO email, NO OTP — the mint is
// open and sybil-resistance is STRUCTURAL (uninvited ids are isolated + undiscoverable), not a server
// gate. This forwards ONLY the canonical 4-key body + key_version (+ optional display_name). Allowlist
// firewall: only known fields pass. (The authority's /verify must have its OTP entry-gate REMOVED —
// Athena's REMOVE-OTP task; until that lands, the client enroll flag isCanonicalEnrollLive stays off.)
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const SHORT_MAX = 4096;
const KEY_B64_MAX = 8192; // ML-DSA-87 pubkey b64 is ~3456 chars; generous ceiling

// String fields forwarded verbatim (length-capped).
const ALLOWED_STRING_FIELDS = [
  'fingerprint',
  'public_key',
  'x25519_pk',
  'mlkem768_pk',
  'mldsa65_pk',
  'display_name',
] as const;

export async function POST(request: NextRequest) {
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    const body: Record<string, unknown> = {};
    for (const key of ALLOWED_STRING_FIELDS) {
      const max = key.endsWith('_pk') || key === 'public_key' ? KEY_B64_MAX : SHORT_MAX;
      if (key in raw && typeof raw[key] === 'string' && (raw[key] as string).length <= max) {
        body[key] = raw[key];
      }
    }
    // key_version is an integer (1=classical, 2=hybrid PQ). Coerce + bound.
    if (typeof raw.key_version === 'number' && Number.isInteger(raw.key_version) && raw.key_version >= 1 && raw.key_version <= 8) {
      body.key_version = raw.key_version;
    }
    if (!body.fingerprint || !body.public_key) {
      return NextResponse.json({ error: 'fingerprint and public_key are required' }, { status: 400 });
    }
    const res = await fetch(`${SATELLITE_URL}/verify`, {
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
