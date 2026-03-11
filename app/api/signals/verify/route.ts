// app/api/signals/verify/route.ts
// Server-side signal verification — looks up sender's public keys.

import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { verifySignal } from '@/lib/trust/signals';
import { base64ToPublicKey } from '@/lib/crypto/hybrid';
import type { SignedSignal } from '@/lib/trust/types';

const identityManager = new SoverentityIdentity();

export async function POST(request: Request) {
  try {
    const { signal, senderFingerprint } = await request.json();

    if (!signal || !senderFingerprint) {
      return NextResponse.json(
        { error: 'signal and senderFingerprint are required' },
        { status: 400 }
      );
    }

    // Load sender's identity for their public keys
    let senderIdentity;
    try {
      senderIdentity = await identityManager.loadIdentityData(senderFingerprint);
    } catch {
      // Sender not in our local store — can't verify
      return NextResponse.json({
        valid: false,
        error: 'Unknown sender — their identity is not in your local store',
      });
    }

    const senderPublicKey = senderIdentity.identity.public_key;

    // Load PQ signing public key if sender has one
    let pqSigPublicKey: Uint8Array | undefined;
    if (senderIdentity.post_quantum?.sig_public_key) {
      pqSigPublicKey = base64ToPublicKey(senderIdentity.post_quantum.sig_public_key);
    }

    const valid = await verifySignal(
      signal as SignedSignal,
      senderPublicKey,
      pqSigPublicKey
    );

    return NextResponse.json({
      valid,
      senderName: senderIdentity.identity.name,
      pqVerified: !!signal.pq_signature && !!pqSigPublicKey,
    });
  } catch (error) {
    console.error('Signal verification error:', error);
    return NextResponse.json(
      { valid: false, error: 'Verification failed' },
      { status: 500 }
    );
  }
}
