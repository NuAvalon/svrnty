// app/api/contacts/share/route.ts
// Create a signed identity exchange package for sharing with peers.
// Dual-signed: ED25519 + ML-DSA-65.

import { NextResponse } from 'next/server';
import { ContactExchange } from '@/lib/contacts/exchange';

const contactExchange = new ContactExchange();

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { fingerprint, type, recipientFingerprint, expireInHours } = body;

    if (!fingerprint) {
      return NextResponse.json(
        { error: 'Fingerprint is required' },
        { status: 400 }
      );
    }

    // Create a signed exchange package
    const exchangePackage = await contactExchange.createExchangePackage({
      senderFingerprint: fingerprint,
      recipientFingerprint: recipientFingerprint || undefined,
      expireInHours: expireInHours || (type === 'burner' ? 48 : 0),
    });

    return NextResponse.json({
      success: true,
      exchangePackage,
      // For backward compat with QR/burner UI
      ...(type === 'qr' && { qrData: exchangePackage }),
      ...(type === 'burner' && { burnerLink: `svrnty://import/${Buffer.from(exchangePackage).toString('base64url').slice(0, 32)}` }),
    });

  } catch (error) {
    console.error('Failed to create exchange package:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Failed to create exchange package' },
      { status: 500 }
    );
  }
}
