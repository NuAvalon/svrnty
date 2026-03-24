// app/api/identity/check/route.ts
// Identity check is now client-side (IndexedDB).
// This route exists only for backwards compatibility — returns
// a hint to use client-side storage.
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({
    exists: false,
    identities: [],
    _note: 'Identity storage is client-side (IndexedDB). Check svrntyDB in the browser.',
  });
}
