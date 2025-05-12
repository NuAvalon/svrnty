// app/api/contacts/share/route.ts
// A super simplified version that doesn't rely on any complex cryptography

import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';

const identityManager = new SoverentityIdentity();

export async function POST(request: Request) {
  console.log('API route hit: /api/contacts/share [POST]');
  
  try {
    const body = await request.json();
    console.log('Received share request:', body);
    
    const { fingerprint, type, expireInHours = 48 } = body;
    
    if (!fingerprint || !type) {
      return NextResponse.json(
        { error: 'Fingerprint and share type are required' },
        { status: 400 }
      );
    }
    
    try {
      // Attempt to load the identity
      const identity = await identityManager.loadIdentityData(fingerprint);
      
      if (!identity) {
        return NextResponse.json(
          { error: 'Identity not found' },
          { status: 404 }
        );
      }
      
      if (type === 'qr') {
        // Generate a simple QR code data
        const simpleQrData = JSON.stringify({
          name: identity.identity.name,
          email: identity.identity.email,
          fingerprint: identity.identity.fingerprint,
          public_key: identity.identity.public_key,
          expires: new Date(Date.now() + (expireInHours || 24) * 60 * 60 * 1000).toISOString()
        });
        
        return NextResponse.json({
          success: true,
          qrData: simpleQrData
        });
      }
      
      if (type === 'burner') {
        // Generate a burner link
        const burnerLink = `https://soverentity.app/contact/${fingerprint.substring(0, 8)}`;
        
        return NextResponse.json({
          success: true,
          burnerLink
        });
      }
      
      return NextResponse.json(
        { error: 'Invalid share type' },
        { status: 400 }
      );
      
    } catch (error) {
      console.error('Failed to load identity:', error);
      return NextResponse.json(
        { error: 'Failed to load identity' },
        { status: 500 }
      );
    }
    
  } catch (error) {
    console.error('Failed to share contact:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to share contact' },
      { status: 500 }
    );
  }
}