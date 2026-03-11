// app/api/signals/sign/route.ts
// Server-side signal signing — private keys never leave the server.

import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { createSignal } from '@/lib/trust/signals';
import type { TrustSignal } from '@/lib/trust/types';

const identityManager = new SoverentityIdentity();

export async function POST(request: Request) {
  try {
    const { fingerprint, payload, recipientFingerprint } = await request.json();

    if (!fingerprint || !payload || !recipientFingerprint) {
      return NextResponse.json(
        { error: 'fingerprint, payload, and recipientFingerprint are required' },
        { status: 400 }
      );
    }

    // Load classical private key
    const keyData = await identityManager.loadKey(fingerprint);

    // Load PQ signing secret key (if available)
    const pqBundle = await identityManager.loadPQKeys(fingerprint);
    const pqSigningSecretKey = pqBundle?.signing?.secretKey ?? undefined;

    // Create and sign the signal
    const signedSignal = await createSignal(
      payload as TrustSignal,
      fingerprint,
      recipientFingerprint,
      keyData.privateKey,
      keyData.passphrase,
      pqSigningSecretKey
    );

    return NextResponse.json({ success: true, signal: signedSignal });
  } catch (error) {
    console.error('Signal signing error:', error);
    return NextResponse.json(
      { error: 'Failed to sign signal' },
      { status: 500 }
    );
  }
}
