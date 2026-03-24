// app/api/vault/route.ts
// Vault export/import is now fully client-side.
// Identity, keys, contacts, and trust graph all live in IndexedDB.
// Encryption/decryption happens in the browser using WebCrypto.
// This route is a stub for backwards compatibility.
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({
    error: 'Vault export has moved client-side. Build the vault from IndexedDB in the browser.',
    _migration: 'Read identity + keys + contacts from svrntyDB, encrypt with AES-256-GCM, download as .svrnty file.',
  }, { status: 410 });
}

export async function POST() {
  return NextResponse.json({
    error: 'Vault import has moved client-side. Decrypt and hydrate IndexedDB in the browser.',
    _migration: 'Decrypt .svrnty file with password, write identity + keys + contacts to svrntyDB.',
  }, { status: 410 });
}
