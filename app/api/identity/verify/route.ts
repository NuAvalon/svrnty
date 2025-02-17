// Add at the top of your verify/route.ts
console.log('Environment variables:', {
    EMAIL_USER: process.env.EMAIL_USER,
    // Don't log the actual password, just check if it exists
    HAS_PASSWORD: !!process.env.EMAIL_PASSWORD
  });

// app/api/identity/verify/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { sendVerificationEmail } from '@/lib/mail';
import { randomBytes } from 'crypto';

const identityManager = new SoverentityIdentity();

// Store verification codes temporarily (in production, use Redis or similar)
const verificationCodes = new Map<string, { code: string, expires: Date }>();

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
  
      // Generate verification code
      const code = randomBytes(3).toString('hex').toUpperCase();
      console.log('Generated verification code:', code);
  
      // Attempt to send email
      console.log('Attempting to send verification email...');
      const emailSent = await sendVerificationEmail(value, code);
      console.log('Email send result:', emailSent);
  
      if (!emailSent) {
        return NextResponse.json(
          { error: 'Failed to send verification email' },
          { status: 500 }
        );
      }
  
      verificationCodes.set(fingerprint, {
        code,
        expires: new Date(Date.now() + 15 * 60 * 1000)
      });
  
      return NextResponse.json({
        success: true,
        message: 'Verification code sent'
      });
    } catch (error) {
      console.error('Verification error:', error);
      return NextResponse.json(
        { success: false, error: 'Failed to start verification' },
        { status: 500 }
      );
    }
  }

// Add route for verifying the code
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
  
      const storedVerification = verificationCodes.get(fingerprint);
      if (!storedVerification) {
        return NextResponse.json(
          { error: 'No verification in progress' },
          { status: 400 }
        );
      }
  
      // Load the identity to get the email
      const identity = await identityManager.loadIdentityData(fingerprint);
      
      if (!identity) {
        return NextResponse.json(
          { error: 'Identity not found' },
          { status: 404 }
        );
      }
  
      if (new Date() > storedVerification.expires) {
        verificationCodes.delete(fingerprint);
        return NextResponse.json(
          { error: 'Verification code expired' },
          { status: 400 }
        );
      }
  
      if (storedVerification.code !== code) {
        return NextResponse.json(
          { error: 'Invalid verification code' },
          { status: 400 }
        );
      }
  
      // Code is valid, verify the identity using the stored email
      const result = await identityManager.verifyIdentifier({
        fingerprint,
        type: 'email',
        value: identity.identity.email
      });
  
      verificationCodes.delete(fingerprint);
  
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
