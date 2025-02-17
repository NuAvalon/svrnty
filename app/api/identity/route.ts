// app/api/identity/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';

// Initialize the identity instance outside the handler
const identityManager = new SoverentityIdentity();

export async function POST(request: Request) {
  console.log('API route hit: /api/identity [POST]');
  
  try {
    const body = await request.json();
    console.log('Received request body:', body);

    const { name, email } = body;
    
    if (!name || !email) {
      console.log('Validation failed:', { name, email });
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      );
    }

    console.log('Creating identity for:', { name, email });
    const result = await identityManager.generateIdentity({ name, email });
    console.log('Generated identity result:', result);

    const response = {
      success: true,
      identity: result.identity,
      fingerprint: result.fingerprint
    };
    
    console.log('Sending response:', response);
    return NextResponse.json(response);
    
  } catch (error) {
    console.error('API Error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to create identity' },
      { status: 500 }
    );
  }
}