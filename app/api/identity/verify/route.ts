// app/api/identity/verify/route.ts
import { NextResponse } from 'next/server';
import { randomBytes } from 'crypto';

// In-memory store for verification codes (in production, use Redis or similar)
const verificationCodes = new Map<string, { code: string; expires: number; email: string }>();

// Email sending function (mock implementation for development)
async function sendVerificationEmail(email: string, code: string): Promise<boolean> {
  console.log(`📧 Verification email would be sent to ${email} with code: ${code}`);
  console.log(`🔑 Use this code to verify: ${code}`);
  // In production, replace with actual email service
  return true;
}

// POST - Send verification code
export async function POST(request: Request) {
  console.log('🔍 API route hit: /api/identity/verify [POST]');
  
  try {
    const body = await request.json();
    const { fingerprint, type, value } = body;
    
    console.log('📝 Verification request:', { fingerprint, type, value });
    
    if (!fingerprint || !type || !value) {
      return NextResponse.json(
        { error: 'Fingerprint, type, and value are required' },
        { status: 400 }
      );
    }

    // For decentralized identities, we don't need to check server files
    // The client will handle identity validation
    console.log('✅ Processing verification for decentralized identity:', fingerprint);

    if (type === 'email') {
      // Generate verification code
      const code = randomBytes(3).toString('hex').toUpperCase(); // 6-digit hex code
      const expires = Date.now() + (15 * 60 * 1000); // 15 minutes
      
      // Store verification code
      verificationCodes.set(fingerprint, { code, expires, email: value });
      
      // Send email (mock for development)
      const emailSent = await sendVerificationEmail(value, code);
      console.log('📧 Email send result:', emailSent);
      
      if (!emailSent) {
        return NextResponse.json(
          { error: 'Failed to send verification email' },
          { status: 500 }
        );
      }
      
      console.log('✅ Verification code generated and stored');
      
      return NextResponse.json({
        success: true,
        message: 'Verification code sent to your email',
        expires: new Date(expires).toISOString()
      });
    }
    
    return NextResponse.json(
      { error: 'Unsupported verification type' },
      { status: 400 }
    );
    
  } catch (error) {
    console.error('❌ Failed to initiate verification:', error);
    return NextResponse.json(
      { 
        error: 'Failed to initiate verification',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}

// PUT - Verify code and update browser storage
export async function PUT(request: Request) {
  console.log('🔍 API route hit: /api/identity/verify [PUT]');
  
  try {
    const body = await request.json();
    const { fingerprint, code } = body;
    
    console.log('🔑 Verifying code for fingerprint:', fingerprint);
    
    if (!fingerprint || !code) {
      return NextResponse.json(
        { error: 'Fingerprint and code are required' },
        { status: 400 }
      );
    }

    // Get stored verification code
    const storedVerification = verificationCodes.get(fingerprint);
    if (!storedVerification) {
      console.error('❌ No verification code found for fingerprint:', fingerprint);
      return NextResponse.json(
        { error: 'No verification code found. Please request a new code.' },
        { status: 400 }
      );
    }

    // Check if code has expired
    if (Date.now() > storedVerification.expires) {
      verificationCodes.delete(fingerprint);
      console.error('⏰ Verification code expired');
      return NextResponse.json(
        { error: 'Verification code has expired. Please request a new code.' },
        { status: 400 }
      );
    }

    // Check if code matches
    if (code.toUpperCase() !== storedVerification.code) {
      console.error('❌ Invalid verification code provided');
      return NextResponse.json(
        { error: 'Invalid verification code' },
        { status: 400 }
      );
    }

    // For decentralized identities, return success with instructions
    // The client will handle updating the identity in browser storage
    console.log('🎉 Verification code validated successfully');
    
    // Clean up verification code
    verificationCodes.delete(fingerprint);

    return NextResponse.json({
      success: true,
      fingerprint,
      message: 'Identity verified successfully',
      // Include the verification data for client-side update
      verification: {
        status: 'verified',
        method: 'email',
        verified_at: new Date().toISOString(),
        email: storedVerification.email
      }
    });
    
  } catch (error) {
    console.error('❌ Failed to verify code:', error);
    return NextResponse.json(
      { 
        error: 'Failed to verify code',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}