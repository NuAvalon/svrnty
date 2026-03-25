// Proxy slug lookup to registration API
import { NextResponse } from 'next/server';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ name: string }> }
) {
  const { name } = await params;
  try {
    // First check if slug is claimed
    const slugRes = await fetch(
      `http://registration:8101/slug/${encodeURIComponent(name)}`,
      { cache: 'no-store' }
    );
    if (!slugRes.ok) return NextResponse.json({ error: 'Not found' }, { status: 404 });
    const slugData = await slugRes.json();
    if (slugData.available) return NextResponse.json({ error: 'Not found' }, { status: 404 });

    // Slug is claimed — get full identity
    const idRes = await fetch(
      `http://registration:8101/u/${encodeURIComponent(name)}`,
      { cache: 'no-store' }
    );
    if (idRes.ok) {
      return NextResponse.json(await idRes.json());
    }
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  } catch {
    return NextResponse.json({ error: 'Service unavailable' }, { status: 503 });
  }
}
