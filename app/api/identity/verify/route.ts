// app/api/identity/verify/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { sendVerificationEmail } from '@/lib/mail';
import { randomBytes, timingSafeEqual } from 'crypto';

const identityManager = new SoverentityIdentity();

// Store verification codes temporarily (in production, use Redis or similar)
const verificationCodes = new Map<string, { code: string, expires: Date, attempts: number }>();

// Rate limiting: track last request per fingerprint
const rateLimits = new Map<string, number>();
const RATE_LIMIT_MS = 60_000; // 1 minute between requests
const MAX_ATTEMPTS = 5;

export async function POST(request: Request) {
    try {
      const body = await request.json();
      const { fingerprint, type, value } = body;

      if (!fingerprint || !type || !value) {
        return NextResponse.json(
          { error: 'Missing required fields' },
          { status: 400 }
        );
      }

      // Rate limiting
      const lastRequest = rateLimits.get(fingerprint);
      if (lastRequest && Date.now() - lastRequest < RATE_LIMIT_MS) {
        return NextResponse.json(
          { error: 'Please wait before requesting another code' },
          { status: 429 }
        );
      }

      // Generate verification code
      const code = randomBytes(3).toString('hex').toUpperCase();

      const emailSent = await sendVerificationEmail(value, code);

      if (!emailSent) {
        return NextResponse.json(
          { error: 'Failed to send verification email' },
          { status: 500 }
        );
      }

      verificationCodes.set(fingerprint, {
        code,
        expires: new Date(Date.now() + 15 * 60 * 1000),
        attempts: 0
      });
      rateLimits.set(fingerprint, Date.now());

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

// Verify the code
export async function PUT(request: Request) {
    try {
      const { fingerprint, code } = await request.json();

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

      // Attempt limiting
      if (storedVerification.attempts >= MAX_ATTEMPTS) {
        verificationCodes.delete(fingerprint);
        return NextResponse.json(
          { error: 'Too many attempts. Request a new code.' },
          { status: 429 }
        );
      }
      storedVerification.attempts++;

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

      // Constant-time comparison to prevent timing attacks
      const codeBuffer = Buffer.from(code.toUpperCase().padEnd(6, '\0'));
      const storedBuffer = Buffer.from(storedVerification.code.padEnd(6, '\0'));
      if (!timingSafeEqual(codeBuffer, storedBuffer)) {
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
