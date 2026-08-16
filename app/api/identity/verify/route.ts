// app/api/identity/verify/route.ts
// Email OTP verification has moved client-side / to the registration satellite.
// This route previously used server-side SoverentityIdentity (~/.soverentity)
// and bound OTP to a client-supplied email while verifying the stored email —
// a fingerprint-only attack. Do not restore server-side identity verification.
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json(
    {
      error: 'Identity verification has moved client-side. Use the registration satellite OTP flow (/register, /verify) or IndexedDB verification status.',
      _migration: 'Never mint or verify identity material on this Next process.',
    },
    { status: 410 }
  );
}

export async function POST() {
  return NextResponse.json(
    {
      error: 'Identity verification has moved client-side. Use the registration satellite OTP flow (/register, /verify) or IndexedDB verification status.',
      _migration: 'Never mint or verify identity material on this Next process.',
    },
    { status: 410 }
  );
}

export async function PUT() {
  return NextResponse.json(
    {
      error: 'Identity verification has moved client-side. Use the registration satellite OTP flow (/register, /verify) or IndexedDB verification status.',
      _migration: 'Never mint or verify identity material on this Next process.',
    },
    { status: 410 }
  );
}

export async function DELETE() {
  return NextResponse.json(
    {
      error: 'Identity verification has moved client-side.',
    },
    { status: 410 }
  );
}
