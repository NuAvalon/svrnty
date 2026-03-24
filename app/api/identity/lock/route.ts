// app/api/identity/lock/route.ts
// Passphrase management is now client-side.
// Hash + salt stored in IndexedDB alongside the identity.
// The server never sees your passphrase.
import { NextResponse } from 'next/server';

export async function POST() {
  return NextResponse.json({
    error: 'Passphrase management has moved client-side. Use the svrntyDB IndexedDB store.',
    _migration: 'Store {hash, salt, created_at} in IndexedDB under the identity fingerprint.',
  }, { status: 410 }); // 410 Gone
}
