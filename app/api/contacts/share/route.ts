// app/api/contacts/share/route.ts
import { NextResponse } from 'next/server';
import { ContactExchange } from '@/lib/contacts/exchange';
import { SoverentityIdentity } from '@/lib/identity/core';

const contactExchange = new ContactExchange();
const identityManager = new SoverentityIdentity();

export async function POST(request: Request) {
  console.log('API route hit: /api/contacts/share [POST]');
  
  try {
    const body = await request.json();
    console.log('Received share request:', body);
    
    const { fingerprint, type, expireInHours = 48, recipientFingerprint } = body;
    
    if (!fingerprint || !type) {
      return NextResponse.json(
        { error: 'Fingerprint and share type are required' },
        { status: 400 }
      );
    }
    
    // Check if the identity exists
    try {
      await identityManager.loadIdentityData(fingerprint);
    } catch (error) {
      return NextResponse.json(
        { error: 'Identity not found' },
        { status: 404 }
      );
    }
    
    if (type === 'qr') {
      // Generate QR code data
      const qrData = await contactExchange.generateQRCodeData(fingerprint);
      
      return NextResponse.json({
        success: true,
        qrData
      });
      
    } else if (type === 'burner') {
      // Generate burner link
      const burnerLink = await contactExchange.createBurnerLink(
        fingerprint,
        expireInHours
      );
      
      return NextResponse.json({
        success: true,
        burnerLink
      });
      
    } else if (type === 'direct' && recipientFingerprint) {
      // Create directed exchange package
      const exchangeData = await contactExchange.createExchangePackage({
        senderFingerprint: fingerprint,
        recipientFingerprint,
      });
      
      return NextResponse.json({
        success: true,
        exchangeData
      });
      
    } else {
      return NextResponse.json(
        { error: 'Invalid share type or missing recipient for direct share' },
        { status: 400 }
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