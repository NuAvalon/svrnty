// Same-origin proxy for the satellite /route/{route_id} POLL endpoint (S6 consent-delta / #558 keystone).
//
// The recipient's client (httpOnionRelay.poll, src/lib/sync/onion-transport.ts) GETs the inner
// cells buffered at a blinded, rotating route_id (K1 route-ratchet: deriveRouteId = 128-bit tag = 32 hex
// chars, route-ratchet.ts:14/63/105). The satellite returns the device-sealed, mailbox_fp-STRIPPED inner
// cells for that route_id (KB#91430: return-by-route_id; K0-1 blinding already applied server-side). The
// response body is opaque sealed ciphertext — this proxy relays it verbatim and strips NOTHING, the same
// no-strip discipline as the /onion deposit proxy (the #179 lesson, both directions).
//
// route_id is shape-bound to 32-hex (KB#91430 — "no arbitrary-blob-store"; matches deriveRouteId). We
// validate that shape here to reject path traversal / arbitrary lookups before they ever reach the
// satellite. Range-polling a catch-up window = one GET per past window (consent-delta-transport.ts
// HORIZON_WINDOWS); each route_id is independently blinded, so the proxy learns no linkage.
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const ROUTE_ID_RE = /^[0-9a-fA-F]{32}$/;

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ route_id: string }> },
) {
  try {
    const { route_id } = await params;
    if (!ROUTE_ID_RE.test(route_id)) {
      return NextResponse.json({ error: 'Invalid route_id' }, { status: 400 });
    }

    const res = await fetch(`${SATELLITE_URL}/route/${route_id}`);
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
