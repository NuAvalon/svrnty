// app/api/identity/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';

const identity = new SoverentityIdentity();

export async function POST(request: Request) {
  try {
    console.log('API route hit');
    const body = await request.json();
    console.log('Received request body:', body);

    const { name, email } = body;
    
    if (!name || !email) {
      console.log('Missing required fields');
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      );
    }

    const result = await identity.generateIdentity({ name, email });
    console.log('Generated identity result:', result);

    // Ensure we're returning valid JSON
    return NextResponse.json({
      success: true,
      identity: result
    });
  } catch (error) {
    console.error('Failed to create identity:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to create identity' },
      { status: 500 }
    );
  }
}

export async function PUT(request: Request) {
  try {
    const { fingerprint, type, value } = await request.json();
    
    if (!fingerprint || !type || !value) {
      return NextResponse.json(
        { error: 'Fingerprint, type, and value are required' },
        { status: 400 }
      );
    }

    const result = await identity.verifyIdentifier({ fingerprint, type, value });
    return NextResponse.json(result);
  } catch (error) {
    console.error('Failed to verify identity:', error);
    return NextResponse.json(
      { error: 'Failed to verify identity' },
      { status: 500 }
    );
  }
}