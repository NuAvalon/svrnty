import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json(
    { error: 'This endpoint has been removed. Identity and contacts are now stored client-side in IndexedDB.' },
    { status: 410 }
  );
}

export async function POST() {
  return NextResponse.json(
    { error: 'This endpoint has been removed. Identity and contacts are now stored client-side in IndexedDB.' },
    { status: 410 }
  );
}

export async function PUT() {
  return NextResponse.json(
    { error: 'This endpoint has been removed. Identity and contacts are now stored client-side in IndexedDB.' },
    { status: 410 }
  );
}

export async function DELETE() {
  return NextResponse.json(
    { error: 'This endpoint has been removed. Identity and contacts are now stored client-side in IndexedDB.' },
    { status: 410 }
  );
}
