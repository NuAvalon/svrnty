// Same-origin proxy for satellite /trust/psi/*. Allowlisted JSON only — device-local
// tags / blocked flags / group labels are never forwarded.
import { pickPsiBody } from '@/lib/sync/psi-proxy-body';
import { NextRequest, NextResponse } from 'next/server';

const SATELLITE_URL = process.env.SATELLITE_URL || 'http://registration:8101';

const PATH_RE = /^[A-Za-z0-9_./-]+$/;

async function proxy(request: NextRequest, path: string, method: 'GET' | 'POST') {
  if (!PATH_RE.test(path) || path.includes('..')) {
    return NextResponse.json({ error: 'Invalid path' }, { status: 400 });
  }
  const search = request.nextUrl.search;
  const url = `${SATELLITE_URL}/trust/psi/${path}${search}`;
  const headers: Record<string, string> = {};
  const sig = request.headers.get('X-Signature');
  if (sig) headers['X-Signature'] = sig;

  let res: Response;
  if (method === 'GET') {
    res = await fetch(url, { headers });
  } else {
    let raw: unknown;
    try {
      raw = await request.json();
    } catch {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }
    headers['Content-Type'] = 'application/json';
    res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(pickPsiBody(raw)) });
  }
  const text = await res.text();
  try {
    return NextResponse.json(JSON.parse(text), { status: res.status });
  } catch {
    return new NextResponse(text, { status: res.status });
  }
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  try {
    const { path } = await params;
    return await proxy(request, (path || []).join('/'), 'GET');
  } catch {
    return NextResponse.json({ error: 'PSI service unavailable' }, { status: 502 });
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  try {
    const { path } = await params;
    return await proxy(request, (path || []).join('/'), 'POST');
  } catch {
    return NextResponse.json({ error: 'PSI service unavailable' }, { status: 502 });
  }
}
