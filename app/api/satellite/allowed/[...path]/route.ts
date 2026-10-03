// Same-origin proxy for satellite /allowed/* — the mutual-connection (allowed_senders) wiring that
// PSI /initiate's mutual-gate reads (satellite.py:3557 "both parties in each other's allowed_senders").
//
// WHY THIS EXISTS (AND-gate b, flip-blocker): the trust_commitments->allowed_senders refactor orphaned
// the live connect-flow — the client wrote /trust/commit, whose satellite handler is gone (the table is
// migrated-once-at-boot then DROPped), so real users had NO path to populate allowed_senders and PSI
// discovery was unsatisfiable for everyone. This proxy forwards the signed ops the rewired client needs:
//   POST   /allowed/{owner}            add    — body {sender_fingerprint, signature}
//                                              signature = Ed25519(bound sig key, 'svrnty-allowed-add:{owner}:{sender}:{unix}'), wire '{unix}:{b64sig}'
//   DELETE /allowed/{owner}/{sender}   revoke — X-Signature header ('svrnty-allowed-remove:...')
//   GET    /allowed/{owner}[/inbound]  list   — X-Signature header
//
// The DELETE is the #111-satellite-completeness leg: client-side fix#2 only stops the SURVIVOR's client
// from revealing; without the satellite-side revoke, a blocked adversary's stale allowed_senders entry
// keeps the mutual-gate open so THEIR client still discovers the survivor. Block/untrust must DELETE here.
//
// Allowlisted (same discipline as the #181 bind proxy): POST forwards only {sender_fingerprint, signature};
// DELETE/GET carry only the X-Signature header. Path is charset-guarded (no traversal). Dark until the
// client connect/trust flow is rewired to call it (Apollo) + isPSIDiscoveryLive flips.
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const PATH_RE = /^[A-Za-z0-9_./-]+$/;

function joinPath(path: string[] | undefined): string | null {
  const p = (path || []).join('/');
  if (!p || !PATH_RE.test(p) || p.includes('..')) return null;
  return p;
}

function relay(text: string, status: number): NextResponse {
  try {
    return NextResponse.json(JSON.parse(text), { status });
  } catch {
    return new NextResponse(text, { status });
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  try {
    const { path } = await params;
    const p = joinPath(path);
    if (!p) return NextResponse.json({ error: 'Invalid path' }, { status: 400 });

    let raw: unknown;
    try {
      raw = await request.json();
    } catch {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    const r = raw as Record<string, unknown>;
    const body: Record<string, unknown> = {};
    for (const key of ['sender_fingerprint', 'signature'] as const) {
      const v = r[key];
      if (typeof v === 'string' && v.length <= 8192) body[key] = v;
    }
    if (!body.sender_fingerprint || !body.signature) {
      return NextResponse.json(
        { error: 'sender_fingerprint and signature are required' },
        { status: 400 },
      );
    }

    const res = await fetch(`${SATELLITE_URL}/allowed/${p}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return relay(await res.text(), res.status);
  } catch {
    return NextResponse.json({ error: 'allowed service unavailable' }, { status: 502 });
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  try {
    const { path } = await params;
    const p = joinPath(path);
    if (!p) return NextResponse.json({ error: 'Invalid path' }, { status: 400 });

    const headers: Record<string, string> = {};
    const sig = request.headers.get('X-Signature');
    if (sig) headers['X-Signature'] = sig;

    const res = await fetch(`${SATELLITE_URL}/allowed/${p}`, { method: 'DELETE', headers });
    return relay(await res.text(), res.status);
  } catch {
    return NextResponse.json({ error: 'allowed service unavailable' }, { status: 502 });
  }
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  try {
    const { path } = await params;
    const p = joinPath(path);
    if (!p) return NextResponse.json({ error: 'Invalid path' }, { status: 400 });

    const headers: Record<string, string> = {};
    const sig = request.headers.get('X-Signature');
    if (sig) headers['X-Signature'] = sig;

    const res = await fetch(`${SATELLITE_URL}/allowed/${p}`, { headers });
    return relay(await res.text(), res.status);
  } catch {
    return NextResponse.json({ error: 'allowed service unavailable' }, { status: 502 });
  }
}
