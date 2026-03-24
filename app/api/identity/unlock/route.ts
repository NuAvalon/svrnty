// app/api/identity/unlock/route.ts
// Passphrase verification is now client-side.
// The server never sees your passphrase or identity data.
import { NextResponse } from 'next/server';

export async function POST() {
  return NextResponse.json({
    error: 'Passphrase verification has moved client-side. Use the svrntyDB IndexedDB store.',
    _migration: 'Read {hash, salt} from IndexedDB, verify with SHA-256 + timing-safe compare in browser.',
  }, { status: 410 }); // 410 Gone
}
