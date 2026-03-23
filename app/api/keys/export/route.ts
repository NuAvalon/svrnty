// app/api/keys/export/route.ts
// Private Key Export — password-protected download of private keys.
// Returns AES-256-GCM encrypted key bundle as a downloadable .svrnty-keys file.

import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { createCipheriv, randomBytes, scryptSync } from 'crypto';

const identityManager = new SoverentityIdentity();

// POST /api/keys/export
// Body: { fingerprint, password }
// Returns: encrypted key bundle as JSON (client downloads as file)
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { fingerprint, password } = body;

    if (!fingerprint) {
      return NextResponse.json({ error: 'fingerprint required' }, { status: 400 });
    }
    if (!password || password.length < 8) {
      return NextResponse.json(
        { error: 'Password required (minimum 8 characters)' },
        { status: 400 }
      );
    }

    // Load classical keys
    const keyData = await identityManager.loadKey(fingerprint);
    if (!keyData) {
      return NextResponse.json({ error: 'Keys not found' }, { status: 404 });
    }

    // Load PQ keys (optional — may not exist for v1 identities)
    let pqKeys = null;
    try {
      const pqBundle = await identityManager.loadPQKeys(fingerprint);
      if (pqBundle) {
        const { serializeKeypairBundle } = await import('@/lib/crypto/pq');
        pqKeys = serializeKeypairBundle(pqBundle);
      }
    } catch {
      // PQ keys not available
    }

    // Load identity metadata (public info only — for the file header)
    const identity = await identityManager.loadIdentityData(fingerprint);

    // Build the plaintext key bundle
    const keyBundle = JSON.stringify({
      version: '1.0.0',
      format: 'svrnty-keys',
      fingerprint,
      exported_at: new Date().toISOString(),
      classical: {
        privateKey: keyData.privateKey,
        passphrase: keyData.passphrase,
      },
      pq: pqKeys,
    });

    // Encrypt with AES-256-GCM using password-derived key (scrypt)
    const salt = randomBytes(32);
    const derivedKey = scryptSync(password, salt, 32, {
      N: 16384,
      r: 8,
      p: 1,
    });
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', derivedKey, iv);

    let encrypted = cipher.update(keyBundle, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();

    // Build the downloadable file
    const exportFile = {
      format: 'svrnty-keys-encrypted',
      version: '1.0.0',
      fingerprint,
      display_name: identity?.identity?.display_name || null,
      exported_at: new Date().toISOString(),
      encryption: {
        algorithm: 'aes-256-gcm',
        kdf: 'scrypt',
        kdf_params: { N: 16384, r: 8, p: 1 },
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        auth_tag: authTag.toString('base64'),
      },
      encrypted_keys: encrypted,
      includes_pq: pqKeys !== null,
    };

    return NextResponse.json(exportFile);
  } catch (error) {
    console.error('Key export error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to export keys' },
      { status: 500 }
    );
  }
}
