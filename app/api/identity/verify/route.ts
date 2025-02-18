// app/api/identity/verify/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { sendVerificationEmail } from '@/lib/mail';

const identityManager = new SoverentityIdentity();

// Store challenges (in production, use Redis or similar)
const challenges = new Map<string, {
  challenge: string;
  otp: string;
  expires: Date;
}>();

export async function POST(request: Request) {
  console.log('Verification API hit');
  try {
    const body = await request.json();
    console.log('Received verification request:', body);

    const { fingerprint, type, value } = body;
    console.log('Extracted values:', { fingerprint, type, value });
    
    if (!fingerprint || !type || !value) {
      console.log('Missing fields:', { fingerprint, type, value });
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    // Generate PGP-bound challenge
    const verificationData = await identityManager.generateVerificationChallenge(
      fingerprint,
      type as 'email' | 'phone',
      value
    );
    console.log('Generated verification data:', verificationData);

    // Store challenge
    challenges.set(fingerprint, verificationData);

    // Send OTP via email
    const emailSent = await sendVerificationEmail(value, verificationData.otp);
    console.log('Email send result:', emailSent);

    if (!emailSent) {
      return NextResponse.json(
        { error: 'Failed to send verification email' },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Verification code sent',
      challenge: verificationData.challenge
    });
  } catch (error) {
    console.error('Verification error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to start verification' },
      { status: 500 }
    );
  }
}

export async function PUT(request: Request) {
  try {
    const { fingerprint, code } = await request.json();
    console.log('Verifying code for fingerprint:', fingerprint);
    
    if (!fingerprint || !code) {
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    const storedChallenge = challenges.get(fingerprint);
    if (!storedChallenge) {
      return NextResponse.json(
        { error: 'No verification in progress' },
        { status: 400 }
      );
    }

    // Load identity to get email
    const identity = await identityManager.loadIdentityData(fingerprint);
    
    if (!identity) {
      return NextResponse.json(
        { error: 'Identity not found' },
        { status: 404 }
      );
    }

    if (new Date() > storedChallenge.expires) {
      challenges.delete(fingerprint);
      return NextResponse.json(
        { error: 'Verification code expired' },
        { status: 400 }
      );
    }

    if (storedChallenge.otp !== code) {
      return NextResponse.json(
        { error: 'Invalid verification code' },
        { status: 400 }
      );
    }

    // Verify the claim with PGP signature
    const result = await identityManager.verifySignedOTP(
      fingerprint,
      'email',
      identity.identity.email,
      code,
      storedChallenge.challenge
    );

    challenges.delete(fingerprint);

    return NextResponse.json({
      success: true,
      identity: result
    });
  } catch (error) {
    console.error('Failed to verify code:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to verify code' },
      { status: 500 }
    );
  }
}